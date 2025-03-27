import requests
import json
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.storage.jsonstore import JsonStore
from kivy.lang import Builder

API_URL = "http://127.0.0.1:8000"  # Адреса бекенду
TOKEN_FILE = "user_token.json"  # Файл для збереження токена


class LoginScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.store = JsonStore(TOKEN_FILE)

        if self.store.exists("token"):
            self.auto_login()
        else:
            self.show_login_form()

    def show_login_form(self):
        """Відображення форми входу/реєстрації."""
        self.clear_widgets()

        self.add_widget(Label(text="Email:"))
        self.email_input = TextInput(multiline=False)
        self.add_widget(self.email_input)

        self.add_widget(Label(text="Password:"))
        self.password_input = TextInput(password=True, multiline=False)
        self.add_widget(self.password_input)

        self.login_button = Button(text="Login/Register")
        self.login_button.bind(on_press=self.login_register)
        self.add_widget(self.login_button)

        self.status_label = Label(text="")
        self.add_widget(self.status_label)

    def login_register(self, instance):
        """Запит на сервер для входу або реєстрації."""
        email = self.email_input.text
        password = self.password_input.text

        if not email or not password:
            self.status_label.text = "Email і пароль обов'язкові!"
            return

        data = {"email": email, "password": password}
        try:
            response = requests.post(f"{API_URL}/register/", json=data)
            response.raise_for_status()

            if response.status_code == 200:
                login_response = requests.post(f"{API_URL}/login/", json=data)
                login_response.raise_for_status()

                if login_response.status_code == 200:
                    token_data = login_response.json()
                    self.store.put("token", access_token=token_data["access_token"])
                    self.status_label.text = f"Ласкаво просимо, {data['email']}!"
                    self.show_user_info({"user_id": response.json()["user_id"], "email": email, "username": "NewUser"})
                else:
                    self.status_label.text = "Помилка входу після реєстрації"
            else:
                self.status_label.text = response.json().get("detail", "Помилка входу/реєстрації")
        except requests.RequestException as e:
            self.status_label.text = f"Помилка з'єднання: {str(e)}"

    def auto_login(self):
        """Перевірка токена при запуску."""
        token_data = self.store.get("token")
        headers = {"Authorization": f"Bearer {token_data['access_token']}"}
        response = requests.get(f"{API_URL}/user_info/", headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            self.show_user_info(user_data)
        else:
            self.store.delete("token")  # Очищення токена
            self.show_login_form()

    def show_user_info(self, user_data):
        """Відображає інформацію про користувача після входу."""
        self.clear_widgets()
        self.add_widget(Label(text=f"ID: {user_data.get('user_id', 'N/A')}"))
        self.add_widget(Label(text=f"Email: {user_data['email']}"))
        self.add_widget(Label(text=f"Username: {user_data['username']}"))

        logout_button = Button(text="Logout")
        logout_button.bind(on_press=self.logout)
        self.add_widget(logout_button)

    def logout(self, instance):
        """Вихід з аккаунта та повернення на екран входу."""
        self.store.delete("token")
        self.show_login_form()


class LoginApp(App):
    def build(self):
        return LoginScreen()


if __name__ == "__main__":
    Builder.load_file('login_screen.kv')
    LoginApp().run()
