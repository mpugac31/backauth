import requests
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.lang import Builder

API_URL = "http://127.0.0.1:8000/register/"  # Адреса бекенду

class LoginScreen(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)

        # Створення елементів інтерфейсу
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
        """Відправляє запит на сервер для реєстрації або входу."""
        email = self.email_input.text
        password = self.password_input.text

        if not email or not password:
            self.status_label.text = "Email і пароль обов'язкові!"
            return

        data = {"email": email, "password": password}
        response = requests.post(API_URL, json=data)#відправляє джсон повідомлення


        if response.status_code == 200:
            user_data = response.json()#остримує джсон відповідь
            self.status_label.text = f"Ласкаво просимо, {user_data.get('username', 'User')}!"
            self.show_user_info(user_data)
            print(user_data)
        else:
            self.status_label.text = response.json().get("detail", "Помилка входу/реєстрації")

    def show_user_info(self, user_data):
        """Виводить інформацію про користувача після входу або реєстрації."""
        self.clear_widgets()
        if 'email' in user_data:
            self.add_widget(Label(text=f"ID: {user_data.get('user_id', 'N/A')}"))
            self.add_widget(Label(text=f"Email: {user_data['email']}"))
            self.add_widget(Label(text=f"Username: {user_data['username']}"))
        else:
            self.add_widget(Label(text="Помилка: Не вдалося отримати інформацію про користувача"))
        logout_button = Button(text="Logout")
        logout_button.bind(on_press=self.logout)
        self.add_widget(logout_button)

    def logout(self, instance):
        """Вихід з аккаунта та повернення на екран входу."""
        self.clear_widgets()
        self.__init__()  # Перезапуск екрану входу



class LoginApp(App):
    def build(self):
        return LoginScreen()


if __name__ == "__main__":
    Builder.load_file('login_screen.kv')
    LoginApp().run()
