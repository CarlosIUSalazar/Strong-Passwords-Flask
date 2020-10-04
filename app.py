from flask import Flask, render_template, request, flash
from password_strength import PasswordPolicy
from password_strength import PasswordStats

app = Flask(__name__)
policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=1,  # need min. 2 uppercase letters
    numbers=1,  # need min. 2 digits
    strength=0.66 # need a password that scores at least 0.5 with its entropy bits
)
app.config['SECRET_KEY'] = '@#$%^&*('

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        password = request.form.get('password')
        email = request.form.get('email')
        stats = PasswordStats(password)
        checkpolicy = policy.test(password)
        if stats.strength() < 0.66:
            print(stats.strength())
            flash("Password not strong enough. Avoid consecutive characters and easily guessed words.")
            return render_template('form.html')
        else:
            print(stats.strength())
            return render_template('success.html')
    return render_template('form.html')

if __name__ == '__main__':
    app.run(debug = True)