
import flet as ft
import os
from supabase import create_client, Client
from dotenv import load_dotenv
import asyncio
import webbrowser
from urllib.parse import urlparse, parse_qs
import threading
import json
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Nastavenie logovania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Načítanie premenných prostredia
load_dotenv()

class SessionManager:
    """Správa session s možnosťou perzistencie"""
    
    def __init__(self, session_file="session.json"):
        self.session_file = Path(session_file)
        
    def save_session(self, session_data):
        """Uloží session do súboru"""
        try:
            session_info = {
                "access_token": session_data.access_token,
                "refresh_token": session_data.refresh_token,
                "user_id": session_data.user.id if session_data.user else None,
                "expires_at": session_data.expires_at,
                "saved_at": datetime.now().isoformat()
            }
            
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_info, f, indent=2)
                
            logger.info("Session uložená úspešne")
            
        except Exception as e:
            logger.error(f"Chyba pri ukladaní session: {e}")
            
    def load_session(self):
        """Načíta session zo súboru"""
        try:
            if not self.session_file.exists():
                return None
                
            with open(self.session_file, 'r', encoding='utf-8') as f:
                session_info = json.load(f)
                
            logger.info("Session načítaná zo súboru")
            return session_info
            
        except Exception as e:
            logger.error(f"Chyba pri načítavaní session: {e}")
            return None
            
    def clear_session(self):
        """Vymaže uloženú session"""
        try:
            if self.session_file.exists():
                self.session_file.unlink()
                logger.info("Session vymazaná")
        except Exception as e:
            logger.error(f"Chyba pri mazaní session: {e}")

class SecureCallbackHandler(BaseHTTPRequestHandler):
    """Zabezpečený callback handler pre OAuth"""
    
    def __init__(self, auth_app, *args, **kwargs):
        self.auth_app = auth_app
        super().__init__(*args, **kwargs)
        
    def do_GET(self):
        try:
            # Základná bezpečnostná kontrola Host hlavičky
            host = self.headers.get('Host', '')
            if host and not host.startswith('localhost:8000'):
                logger.warning(f"Nepovolený host: {host}")
                self.send_error(403, "Forbidden")
                return
                
            if self.path.startswith('/auth/callback'):
                self.handle_oauth_callback()
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Chyba v callback handleri: {e}")
            self.send_error(500, f"Internal Server Error: {str(e)}")
    
    def handle_oauth_callback(self):
        """Spracuje OAuth callback"""
        try:
            # Parsovanie URL parametrov
            parsed_url = urlparse(self.path)
            
            # Pre debugging - vypíšeme celú URL
            logger.info(f"Callback URL path: {self.path}")
            logger.info(f"Parsed query: {parsed_url.query}")
            logger.info(f"Parsed fragment: {parsed_url.fragment}")
            
            # Supabase OAuth callback má parametre v query, nie vo fragmente
            # Skúsime najprv query, potom fragment
            params = {}
            
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                logger.info(f"Query params: {list(params.keys())}")
            
            # Ak nie sú parametre v query, skús fragment (pre niektoré OAuth flow)
            if not params and parsed_url.fragment:
                params = parse_qs(parsed_url.fragment)
                logger.info(f"Fragment params: {list(params.keys())}")
            
            # Ak stále nie sú parametre, skús parsovať celý path
            if not params:
                # Možno sú parametre priamo v path za callback
                if '?' in self.path:
                    query_part = self.path.split('?', 1)[1]
                    params = parse_qs(query_part)
                    logger.info(f"Path params: {list(params.keys())}")
                elif '#' in self.path:
                    fragment_part = self.path.split('#', 1)[1]
                    params = parse_qs(fragment_part)
                    logger.info(f"Path fragment params: {list(params.keys())}")
            
            logger.info(f"Final params keys: {list(params.keys())}")
            
            # Kontrola či máme potrebné parametre
            if 'code' in params:
                # Authorization code flow
                code = params['code'][0]
                logger.info("Prijatý authorization code")
                
                try:
                    # Exchange code for session
                    session_response = self.auth_app.supabase.auth.exchange_code_for_session({
                        "auth_code": code
                    })
                    
                    if session_response.user:
                        self.auth_app.user = session_response.user
                        
                        # Uloženie session pre perzistenciu
                        self.auth_app.session_manager.save_session(session_response)
                        
                        logger.info(f"Používateľ úspešne prihlásený: {session_response.user.email}")
                        
                        # Úspešná odpoveď
                        self.send_success_response()
                        
                        # Aktualizácia UI v hlavnom vlákne
                        self.auth_app.page.run_thread(
                            lambda: self.auth_app.handle_successful_login()
                        )
                    else:
                        raise Exception("Nepodarilo sa získať používateľské údaje zo session")
                        
                except Exception as session_error:
                    logger.error(f"Chyba pri exchange code: {session_error}")
                    self.send_error_response(f"Chyba pri autentifikácii: {str(session_error)}")
                    
                    # Zobrazenie chyby v UI
                    self.auth_app.page.run_thread(
                        lambda: self.auth_app.show_auth_error(str(session_error))
                    )
                    
            elif 'access_token' in params:
                # Implicit flow (menej bezpečný, ale možný)
                access_token = params['access_token'][0]
                refresh_token = params.get('refresh_token', [None])[0]
                expires_in = params.get('expires_in', [None])[0]
                
                logger.info("OAuth tokeny úspešne prijaté (implicit flow)")
                
                try:
                    session_response = self.auth_app.supabase.auth.set_session(
                        access_token, refresh_token
                    )
                    
                    if session_response.user:
                        self.auth_app.user = session_response.user
                        
                        # Uloženie session pre perzistenciu
                        self.auth_app.session_manager.save_session(session_response)
                        
                        logger.info(f"Používateľ úspešne prihlásený: {session_response.user.email}")
                        
                        # Úspešná odpoveď
                        self.send_success_response()
                        
                        # Aktualizácia UI v hlavnom vlákne
                        self.auth_app.page.run_thread(
                            lambda: self.auth_app.handle_successful_login()
                        )
                    else:
                        raise Exception("Nepodarilo sa získať používateľské údaje zo session")
                        
                except Exception as session_error:
                    logger.error(f"Chyba pri nastavovaní session: {session_error}")
                    self.send_error_response(f"Chyba pri nastavovaní session: {str(session_error)}")
                    
                    # Zobrazenie chyby v UI
                    self.auth_app.page.run_thread(
                        lambda: self.auth_app.show_auth_error(str(session_error))
                    )
                    
            elif 'error' in params:
                # OAuth chyba
                error = params['error'][0]
                error_description = params.get('error_description', [''])[0]
                
                logger.warning(f"OAuth chyba: {error} - {error_description}")
                
                self.send_error_response(f"Chyba pri autentifikácii: {error}")
                
                # Zobrazenie chyby v UI
                self.auth_app.page.run_thread(
                    lambda: self.auth_app.show_auth_error(f"{error}: {error_description}")
                )
                
            else:
                # Debug info pre diagnostiku
                logger.error("Chýbajúce OAuth parametre v callback")
                logger.error(f"Dostupné parametre: {list(params.keys())}")
                logger.error(f"Celá URL: {self.path}")
                
                self.send_error_response(f"Neplatný OAuth callback - chýbajúce parametre. Dostupné: {list(params.keys())}")
                
        except Exception as e:
            logger.error(f"Kritická chyba v OAuth callback: {e}")
            self.send_error_response(f"Kritická chyba: {str(e)}")
    
    
    
    def send_success_response(self):
        """Pošle úspešnú HTML odpoveď"""
        html_response = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Prihlásenie úspešné</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .success { color: #4CAF50; }
                .container { max-width: 400px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2 class="success">✓ Prihlásenie úspešné!</h2>
                <p>Môžete zavrieť túto stránku a vrátiť sa do aplikácie.</p>
                <button onclick="window.close()">Zavrieť okno</button>
            </div>
            <script>
                // Automatické zatvorenie po 3 sekundách
                setTimeout(() => window.close(), 3000);
            </script>
        </body>
        </html>
        """
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_response.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html_response.encode('utf-8'))
        
    def send_error_response(self, error_message):
        """Pošle chybovú HTML odpoveď"""
        html_response = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Chyba pri prihlásení</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .error {{ color: #F44336; }}
                .container {{ max-width: 500px; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2 class="error">✗ Chyba pri prihlásení</h2>
                <p>{error_message}</p>
                <button onclick="window.close()">Zavrieť okno</button>
            </div>
            <script>
                setTimeout(() => window.close(), 5000);
            </script>
        </body>
        </html>
        """
        
        self.send_response(400)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html_response.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html_response.encode('utf-8'))
        
    def log_message(self, format, *args):
        """Vlastné logovanie namiesto štandardného"""
        logger.info(f"HTTP Server: {format % args}")

class GoogleAuthApp:
    def __init__(self):
        # Supabase konfigurácia
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_KEY")
        self.redirect_url = os.getenv("REDIRECT_URL", "http://localhost:8000/auth/callback")
        
        if not self.supabase_url or not self.supabase_key:
            raise ValueError("Chýbajú Supabase premenné prostredia (SUPABASE_URL, SUPABASE_ANON_KEY)")
            
        self.supabase: Client = create_client(self.supabase_url, self.supabase_key)
        self.session_manager = SessionManager()
        self.page = None
        self.user = None
        self.callback_server = None
        
        logger.info("Google Auth App inicializovaná")
        
    def main(self, page: ft.Page):
        self.page = page
        page.title = "Google Auth Demo"
        page.theme_mode = ft.ThemeMode.LIGHT
        page.vertical_alignment = ft.MainAxisAlignment.CENTER
        page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
        page.window.width = 450
        page.window.height = 650
        
        # Pokus o obnovenie session zo súboru
        self.try_restore_session()
        
    def try_restore_session(self):
        """Pokus o obnovenie uloženej session"""
        try:
            # Kontrola aktuálnej session v Supabase
            current_session = self.supabase.auth.get_session()
            if current_session and current_session.user:
                self.user = current_session.user
                logger.info(f"Session obnovená pre: {self.user.email}")
                self.show_dashboard()
                return
                
            # Pokus o načítanie zo súboru
            saved_session = self.session_manager.load_session()
            if saved_session and saved_session.get('access_token'):
                try:
                    # Pokus o obnovenie session
                    session_response = self.supabase.auth.set_session(
                        saved_session['access_token'],
                        saved_session.get('refresh_token')
                    )
                    
                    if session_response.user:
                        self.user = session_response.user
                        logger.info(f"Session obnovená zo súboru pre: {self.user.email}")
                        self.show_dashboard()
                        return
                        
                except Exception as e:
                    logger.warning(f"Nepodarilo sa obnoviť session zo súboru: {e}")
                    self.session_manager.clear_session()
                    
        except Exception as e:
            logger.error(f"Chyba pri obnove session: {e}")
            
        # Ak sa nepodarilo obnoviť session, zobraz login
        self.show_login()
        
    def show_login(self):
        """Zobrazí prihlasovaciu obrazovku"""
        self.page.clean()
        
        # Logo alebo názov aplikácie
        title = ft.Text(
            "Prihlásenie",
            size=32,
            weight=ft.FontWeight.BOLD,
            color=ft.Colors.BLUE_700
        )
        
        subtitle = ft.Text(
            "Prihláste sa pomocou svojho Google účtu",
            size=16,
            color=ft.Colors.GREY_600
        )
        
        # Google prihlásenie tlačidlo
        google_btn = ft.ElevatedButton(
            text="Prihlásiť sa cez Google",
            icon=ft.Icons.LOGIN,
            width=280,
            height=50,
            on_click=self.google_sign_in,
            style=ft.ButtonStyle(
                color=ft.Colors.WHITE,
                bgcolor=ft.Colors.RED_400,
            )
        )
        
        # Status text
        self.status_text = ft.Text(
            "",
            color=ft.Colors.RED_400,
            text_align=ft.TextAlign.CENTER,
            width=350
        )
        
        # Rozloženie
        login_container = ft.Container(
            content=ft.Column([
                title,
                subtitle,
                ft.Container(height=30),
                google_btn,
                ft.Container(height=20),
                self.status_text
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=10
            ),
            padding=40,
            border_radius=10,
            bgcolor=ft.Colors.WHITE,
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.Colors.BLUE_GREY_300,
                offset=ft.Offset(0, 0),
                blur_style=ft.ShadowBlurStyle.OUTER,
            )
        )
        
        self.page.add(login_container)
        self.page.update()
        
    def show_dashboard(self):
        """Zobrazí dashboard po úspešnom prihlásení"""
        self.page.clean()
        
        # Používateľské informácie
        user_info = ft.Column([
            ft.Text(
                "Vitajte!",
                size=28,
                weight=ft.FontWeight.BOLD,
                color=ft.Colors.GREEN_700
            ),
            ft.Text(
                f"📧 {self.user.email}",
                size=16
            ),
            ft.Text(
                f"👤 {self.user.user_metadata.get('full_name', 'Neznáme meno')}",
                size=16
            ) if self.user.user_metadata.get('full_name') else ft.Container(),
            ft.Text(
                f"🆔 {self.user.id[:8]}...",
                size=12,
                color=ft.Colors.GREY_600
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        spacing=5
        )
        
        # Dodatočné informácie
        session_info = ft.Container(
            content=ft.Column([
                ft.Text(
                    "ℹ️ Informácie o session",
                    size=14,
                    weight=ft.FontWeight.BOLD
                ),
                ft.Text(
                    f"Prihlásený: {datetime.now().strftime('%d.%m.%Y %H:%M')}",
                    size=12,
                    color=ft.Colors.GREY_600
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=3
            ),
            padding=15,
            border_radius=8,
            bgcolor=ft.Colors.BLUE_50,
            border=ft.border.all(1, ft.Colors.BLUE_200)
        )
        
        # Tlačidlá
        buttons_row = ft.Row([
            ft.ElevatedButton(
                text="Obnoviť session",
                icon=ft.Icons.REFRESH,
                on_click=self.refresh_session,
                style=ft.ButtonStyle(
                    color=ft.Colors.WHITE,
                    bgcolor=ft.Colors.BLUE_400,
                )
            ),
            ft.ElevatedButton(
                text="Odhlásiť sa",
                icon=ft.Icons.LOGOUT,
                on_click=self.sign_out,
                style=ft.ButtonStyle(
                    color=ft.Colors.WHITE,
                    bgcolor=ft.Colors.RED_400,
                )
            ),
        ],
        alignment=ft.MainAxisAlignment.CENTER,
        spacing=10
        )
        
        # Dashboard obsah
        dashboard_container = ft.Container(
            content=ft.Column([
                user_info,
                ft.Container(height=20),
                session_info,
                ft.Container(height=20),
                ft.Text(
                    "Tu môžete pridať obsah vašej aplikácie",
                    size=14,
                    color=ft.Colors.GREY_600,
                    text_align=ft.TextAlign.CENTER
                ),
                ft.Container(height=30),
                buttons_row
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=10
            ),
            padding=40,
            border_radius=10,
            bgcolor=ft.Colors.WHITE,
            shadow=ft.BoxShadow(
                spread_radius=1,
                blur_radius=15,
                color=ft.Colors.BLUE_GREY_300,
                offset=ft.Offset(0, 0),
                blur_style=ft.ShadowBlurStyle.OUTER,
            )
        )
        
        self.page.add(dashboard_container)
        self.page.update()
        
    def google_sign_in(self, e):
        """Spustí Google OAuth proces"""
        try:
            self.update_status("Spúšťa sa prihlásenie...")
            logger.info("Začína Google OAuth proces")
            
            # Vytvorenie OAuth URL s authority code flow
            auth_response = self.supabase.auth.sign_in_with_oauth({
                "provider": "google",
                "options": {
                    "redirect_to": self.redirect_url,
                    "scopes": "email profile"
                }
            })
            
            if auth_response.url:
                logger.info(f"OAuth URL vytvorená: {auth_response.url}")
                
                # Spustenie callback servera pred otvorením prehliadača
                if self.start_callback_server():
                    # Otvorenie prehliadača pre OAuth
                    webbrowser.open(auth_response.url)
                    self.update_status("Dokončite prihlásenie v prehliadači...")
                else:
                    self.show_auth_error("Nepodarilo sa spustiť callback server")
                    
            else:
                self.show_auth_error("Chyba pri vytváraní OAuth URL")
                
        except Exception as ex:
            logger.error(f"Chyba pri Google sign in: {ex}")
            self.show_auth_error(f"Chyba pri prihlásení: {str(ex)}")
    
    
    def start_callback_server(self):
        """Spustí zabezpečený HTTP server pre OAuth callback"""
        try:
            def create_handler(*args, **kwargs):
                return SecureCallbackHandler(self, *args, **kwargs)
                
            # Kontrola či port nie je už používaný
            try:
                self.callback_server = HTTPServer(('localhost', 8000), create_handler)
                self.callback_server.timeout = 120  # 2 minúty timeout
                
                def run_server():
                    try:
                        logger.info("Callback server spustený na localhost:8000")
                        self.callback_server.handle_request()
                        logger.info("Callback server ukončený")
                    except Exception as e:
                        logger.error(f"Chyba v callback serveri: {e}")
                    finally:
                        if self.callback_server:
                            self.callback_server.server_close()
                            self.callback_server = None
                            
                # Spustenie servera v separátnom vlákne
                server_thread = threading.Thread(target=run_server, daemon=True)
                server_thread.start()
                
                return True
                
            except OSError as e:
                if e.errno == 48:  # Port already in use
                    logger.error("Port 8000 je už používaný")
                    return False
                raise
                
        except Exception as e:
            logger.error(f"Chyba pri spúšťaní callback servera: {e}")
            return False
            
    def handle_successful_login(self):
        """Spracuje úspešné prihlásenie"""
        self.show_dashboard()
        
        # Zobrazenie úspešného dialógu
        success_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Prihlásenie úspešné!"),
            content=ft.Text(f"Vitajte, {self.user.email}!"),
            actions=[
                ft.TextButton("OK", on_click=lambda _: self.close_dialog(success_dialog))
            ]
        )
        
        self.page.dialog = success_dialog
        success_dialog.open = True
        self.page.update()
        
    def show_auth_error(self, error_message):
        """Zobrazí chybový dialóg"""
        logger.error(f"Auth error: {error_message}")
        
        if hasattr(self, 'status_text'):
            self.status_text.value = error_message
            self.status_text.color = ft.Colors.RED_600
            self.page.update()
            
        # Modálny dialóg pre kritické chyby
        error_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Chyba pri prihlásení", color=ft.Colors.RED_600),
            content=ft.Text(error_message),
            actions=[
                ft.TextButton("Skúsiť znovu", on_click=lambda _: self.retry_login(error_dialog)),
                ft.TextButton("OK", on_click=lambda _: self.close_dialog(error_dialog))
            ]
        )
        
        self.page.dialog = error_dialog
        error_dialog.open = True
        self.page.update()
        
    def retry_login(self, dialog):
        """Znovu spustí prihlásenie"""
        self.close_dialog(dialog)
        if hasattr(self, 'status_text'):
            self.status_text.value = ""
            self.page.update()
            
    def close_dialog(self, dialog):
        """Zatvorí dialóg"""
        dialog.open = False
        self.page.update()
        
    def update_status(self, message):
        """Aktualizuje status text"""
        if hasattr(self, 'status_text'):
            self.status_text.value = message
            self.status_text.color = ft.Colors.BLUE_600
            self.page.update()
            
    def refresh_session(self, e):
        """Obnoví session"""
        try:
            session = self.supabase.auth.refresh_session()
            if session and session.user:
                self.user = session.user
                self.session_manager.save_session(session)
                logger.info("Session úspešne obnovená")
                
                # Zobrazenie potvrdenia
                self.show_success_snackbar("Session obnovená")
            else:
                self.show_auth_error("Nepodarilo sa obnoviť session")
                
        except Exception as ex:
            logger.error(f"Chyba pri obnove session: {ex}")
            self.show_auth_error(f"Chyba pri obnove: {str(ex)}")
            
    def show_success_snackbar(self, message):
        """Zobrazí úspešnú snackbar správu"""
        snackbar = ft.SnackBar(
            content=ft.Text(message, color=ft.Colors.WHITE),
            bgcolor=ft.Colors.GREEN_400,
            duration=2000
        )
        self.page.snack_bar = snackbar
        snackbar.open = True
        self.page.update()
        
    def sign_out(self, e):
        """Odhlásenie používateľa"""
        try:
            logger.info(f"Odhlasovanie používateľa: {self.user.email if self.user else 'Unknown'}")
            
            # Ukončenie callback servera ak beží
            if self.callback_server:
                self.callback_server.server_close()
                self.callback_server = None
                
            # Odhlásenie z Supabase
            self.supabase.auth.sign_out()
            
            # Vymazanie uloženej session
            self.session_manager.clear_session()
            
            # Reset stavu
            self.user = None
            
            logger.info("Používateľ úspešne odhlásený")
            self.show_login()
            
        except Exception as ex:
            logger.error(f"Chyba pri odhlásení: {ex}")
            # Aj pri chybe vyresetuj stav
            self.user = None
            self.session_manager.clear_session()
            self.show_login()

def main():
    try:
        app = GoogleAuthApp()
        ft.app(target=app.main, port=8080, view=ft.AppView.FLET_APP)
    except Exception as e:
        logger.critical(f"Kritická chyba pri spúšťaní aplikácie: {e}")
        print(f"Chyba: {e}")

if __name__ == "__main__":
    main()