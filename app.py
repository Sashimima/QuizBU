import re
import random
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# ================== ЗАПРЕЩЁННЫЕ СЛОВА ==================
BANNED_WORDS = (
    'порно', 'секс', 'xxx', 'трах', 'член', 'вагина', 'оргазм',
    'курить', 'сигареты', 'табак', 'кальян', 'вейп', 'спайс',
    'наркотик', 'кокаин', 'героин', 'метадон', 'амфетамин','метамфетамин','лсд','опий','конопля','морфий','крек','экстази','насвай','марихуана','бутерат','гашиш','мефедрон','клафилин','мезапам'
    'алкоголь', 'водка', 'пиво', 'вино', 'коньяк', 'виски','ром','бухло','текила','абсент','бренди','саке'
    'мат', 'хуй', 'пизда', 'ебать', 'блядь','porno','porn','прон','порн','похуй','поебать','похуй','до пизды','допизды','блять','мудак','дура','ахуел','ахуеть','сука','блядина','шлюха','ебанат','пидорас','гандон','ебанутый','ебанутая'
)

app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'quiz_course_2026_secure_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ================== МОДЕЛИ ==================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    quizzes = db.relationship('Quiz', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_private = db.Column(db.Boolean, default=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    questions = db.relationship('Question', backref='quiz', lazy=True, cascade='all, delete-orphan')
    results = db.relationship('Result', backref='quiz', lazy=True, cascade='all, delete-orphan')

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    text = db.Column(db.String(250), nullable=False)
    is_multiple = db.Column(db.Boolean, default=False)
    is_open = db.Column(db.Boolean, default=False)
    options = db.relationship('Option', backref='question', lazy=True, cascade='all, delete-orphan')

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    text = db.Column(db.String(150), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    score = db.Column(db.Float, nullable=False)
    total = db.Column(db.Integer, nullable=False)
    answers_json = db.Column(db.Text)
    date = db.Column(db.DateTime, default=db.func.current_timestamp())

class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    answer_text = db.Column(db.Text, nullable=False)
    normalized = db.Column(db.String(200))
    date = db.Column(db.DateTime, default=db.func.current_timestamp())
    quiz = db.relationship('Quiz', backref=db.backref('user_answers', cascade='all, delete-orphan'))
    question = db.relationship('Question', backref=db.backref('user_answers', cascade='all, delete-orphan'))

# ================== ДЕКОРАТОР ==================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите в систему.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==================
def normalize_text(text):
    if not text:
        return ''
    text = re.sub(r'[^\w\sа-яА-ЯёЁ]', '', text.lower().strip())
    return ' '.join(text.split())

# ================== АУТЕНТИФИКАЦИЯ ==================
@app.before_request
def make_session_username():
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            session['username'] = user.username
        else:
            session.clear()
            session['username'] = 'Гость'
    else:
        session['username'] = 'Гость'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        password2 = request.form.get('password2', '').strip()

        if not username or not password:
            flash('Все поля обязательны', 'danger')
            return render_template('register.html')

        if password != password2:
            flash('Пароли не совпадают', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Пользователь с таким именем уже существует', 'danger')
            return render_template('register.html')

        # проверка имени на запрещённые слова
        for word in BANNED_WORDS:
            if word in username.lower():
                flash('Имя содержит недопустимые слова', 'danger')
                return render_template('register.html')

        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Регистрация успешна! Теперь войдите.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Добро пожаловать, {user.username}!', 'success')
            next_url = session.pop('next_url', None)
            if next_url:
                return redirect(next_url)
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))

# ================== ТЕМА ==================
@app.route('/toggle_theme')
def toggle_theme():
    current = session.get('theme', 'light')
    session['theme'] = 'dark' if current == 'light' else 'light'
    session.modified = True
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return {'theme': session['theme']}
    return redirect(request.referrer or url_for('index'))

# ================== ГЛАВНАЯ ==================
@app.route('/')
def index():
    query = Quiz.query
    search = request.args.get('q', '').strip()
    sort_by = request.args.get('sort', 'popular')

    if search:
        query = query.filter(Quiz.title.ilike(f'%{search}%'))

    # Фильтрация по доступу
    if 'user_id' in session:
        query = query.filter((Quiz.is_private == False) | (Quiz.creator_id == session['user_id']))
    else:
        query = query.filter(Quiz.is_private == False)

    quizzes = query.all()

    if sort_by == 'popular':
        quizzes = sorted(quizzes, key=lambda q: len(q.results), reverse=True)
    elif sort_by == 'new':
        quizzes = sorted(quizzes, key=lambda q: q.id, reverse=True)
    elif sort_by == 'title':
        quizzes = sorted(quizzes, key=lambda q: q.title)

    return render_template('index.html', quizzes=quizzes, search_query=search, sort_by=sort_by)

# ================== СОЗДАНИЕ ВИКТОРИНЫ ==================
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_quiz():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        is_private = 'is_private' in request.form

        if not title:
            flash('❌ Название обязательно!', 'danger')
            return redirect(url_for('create_quiz'))

        # Проверка запрещённых слов
        texts_to_check = [title, description]
        q_texts = request.form.getlist('question_text')
        for t in q_texts:
            if t.strip():
                texts_to_check.append(t.strip())
        for i in range(len(q_texts)):
            opts = request.form.getlist(f'option_{i}')
            for opt in opts:
                if opt.strip():
                    texts_to_check.append(opt.strip())

        for text in texts_to_check:
            if text:
                text_lower = text.lower()
                for word in BANNED_WORDS:
                    if word in text_lower:
                        flash(f'❌ Ваш текст содержит запрещённое слово: «{word}». Исправьте.', 'danger')
                        return redirect(url_for('create_quiz'))

        try:
            quiz = Quiz(
                title=title,
                description=description,
                is_private=is_private,
                creator_id=session['user_id']
            )
            db.session.add(quiz)
            db.session.flush()

            q_texts = request.form.getlist('question_text')
            for i, q_text in enumerate(q_texts):
                q_text = q_text.strip()
                if not q_text:
                    continue
                is_multiple = f'is_multiple_{i}' in request.form
                is_open = f'is_open_{i}' in request.form
                question = Question(quiz_id=quiz.id, text=q_text, is_multiple=is_multiple, is_open=is_open)
                db.session.add(question)
                db.session.flush()

                if not is_open:
                    options = request.form.getlist(f'option_{i}')
                    correct_values = request.form.getlist(f'correct_{i}')
                    for j, opt_text in enumerate(options):
                        opt_text = opt_text.strip()
                        if opt_text:
                            if is_multiple:
                                is_correct = str(j) in correct_values
                            else:
                                is_correct = (str(j) == correct_values[0]) if correct_values else False
                            db.session.add(Option(question_id=question.id, text=opt_text, is_correct=is_correct))

            db.session.commit()
            flash('✅ Викторина создана!', 'success')
            return redirect(url_for('index'))

        except Exception as e:
            db.session.rollback()
            flash(f'❌ Ошибка: {str(e)}', 'danger')
            return redirect(url_for('create_quiz'))

    return render_template('create_quiz.html')

# ================== ПРОХОЖДЕНИЕ ВИКТОРИНЫ ==================
@app.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    # Если викторина приватная, допускаем только авторизованных
    if quiz.is_private and 'user_id' not in session:
        session['next_url'] = request.url
        flash('Для доступа к приватной викторине необходимо войти.', 'warning')
        return redirect(url_for('login'))

    session_key = f'quiz_{quiz_id}'

    if len(quiz.questions) == 0:
        flash('❌ В этой викторине нет вопросов.', 'danger')
        return redirect(url_for('index'))

    # Инициализация состояния (без изменений)
    if session_key not in session:
        shuffled_ids = [q.id for q in quiz.questions]
        random.shuffle(shuffled_ids)
        session[session_key] = {
            'q_ids': shuffled_ids,
            'idx': 0,
            'score': 0,
            'hidden_opts': [],
            'selected_answers': {},
            'open_answers': {}
        }
        session.modified = True
    else:
        state = session[session_key]
        valid_ids = {q.id for q in quiz.questions}
        current_ids = set(state.get('q_ids', []))
        if not current_ids.issubset(valid_ids):
            shuffled_ids = [q.id for q in quiz.questions]
            random.shuffle(shuffled_ids)
            session[session_key] = {
                'q_ids': shuffled_ids,
                'idx': 0,
                'score': 0,
                'hidden_opts': [],
                'selected_answers': {},
                'open_answers': {}
            }
            session.modified = True

    state = session[session_key]
    idx = state['idx']
    total = len(state['q_ids'])

    if idx >= total:
        # Сбор всех ответов
        all_user_answers = {}
        all_user_answers.update(state['selected_answers'])
        all_user_answers.update(state['open_answers'])

        for q_id_str, answer_text in state.get('open_answers', {}).items():
            q_id = int(q_id_str)
            question = Question.query.get(q_id)
            if question and question.is_open:
                user_normalized = normalize_text(answer_text)
                all_answers = UserAnswer.query.filter_by(quiz_id=quiz_id, question_id=q_id).all()
                total_answers = len(all_answers)
                if total_answers > 0:
                    matches = sum(1 for a in all_answers if a.normalized == user_normalized)
                    state['score'] += matches / total_answers

        result = Result(
            quiz_id=quiz_id,
            username=session['username'],
            user_id=session.get('user_id'),
            score=round(state['score'], 2),
            total=total,
            answers_json=json.dumps(all_user_answers, ensure_ascii=False)
        )
        db.session.add(result)
        db.session.commit()

        result_id = result.id
        session.pop(session_key, None)
        return redirect(url_for('quiz_result', result_id=result_id))

    q_id = state['q_ids'][idx]
    question = Question.query.get(q_id)

    if question is None:
        state['q_ids'].remove(q_id)
        session.modified = True
        if state['idx'] >= len(state['q_ids']):
            state['idx'] = 0
        return redirect(url_for('take_quiz', quiz_id=quiz_id))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'hint' and not question.is_open:
            wrong_opts = [opt.id for opt in question.options if not opt.is_correct]
            to_hide = random.sample(wrong_opts, min(2, len(wrong_opts)))
            state['hidden_opts'] = to_hide
            session.modified = True
            return redirect(url_for('take_quiz', quiz_id=quiz_id))

        if action == 'next':
            if question.is_open:
                answer = request.form.get('open_answer', '').strip()
                if answer:
                    state['open_answers'][str(q_id)] = answer
                    db.session.add(UserAnswer(
                        quiz_id=quiz_id, question_id=q_id,
                        username=session['username'],
                        user_id=session.get('user_id'),
                        answer_text=answer,
                        normalized=normalize_text(answer)
                    ))
                    db.session.commit()
            else:
                selected = request.form.getlist('answer')
                selected_ids = [int(s) for s in selected if s.isdigit()]
                correct_ids = [opt.id for opt in question.options if opt.is_correct]
                is_correct = False
                if question.is_multiple:
                    is_correct = set(selected_ids) == set(correct_ids)
                else:
                    is_correct = len(selected_ids) == 1 and selected_ids[0] in correct_ids
                if is_correct:
                    state['score'] += 1
                state['selected_answers'][str(q_id)] = selected_ids

            state['idx'] += 1
            state['hidden_opts'] = []
            session.modified = True
            return redirect(url_for('take_quiz', quiz_id=quiz_id))

        if action == 'save_selection' and not question.is_open:
            selected = request.form.getlist('answer')
            selected_ids = [int(s) for s in selected if s.isdigit()]
            state['selected_answers'][str(q_id)] = selected_ids
            session.modified = True
            return redirect(url_for('take_quiz', quiz_id=quiz_id))

    time_left = 15
    visible_options = list(question.options) if not question.is_open else []
    if 'hidden_opts' in state and state['hidden_opts'] and not question.is_open:
        visible_options = [opt for opt in visible_options if opt.id not in state['hidden_opts']]

    previously_selected = state['selected_answers'].get(str(q_id), [])
    open_answer = state['open_answers'].get(str(q_id), '')

    return render_template('quiz.html', quiz=quiz, question=question,
                          options=visible_options, idx=idx, total=total,
                          time_left=time_left, theme=session.get('theme', 'light'),
                          previously_selected=previously_selected,
                          open_answer=open_answer)
# ================== РЕЗУЛЬТАТ ВИКТОРИНЫ ==================
@app.route('/result/<int:result_id>')
def quiz_result(result_id):
    result = Result.query.get_or_404(result_id)
    quiz = Quiz.query.get(result.quiz_id)
    questions = quiz.questions
    user_answers = json.loads(result.answers_json) if result.answers_json else {}

    details = []
    for q in questions:
        q_id = str(q.id)
        detail = {
            'question': q,
            'user_answer': None,
            'correct': [],
            'is_open': q.is_open
        }
        if q.is_open:
            user_text = user_answers.get(q_id, '')
            detail['user_answer'] = user_text
            freq = db.session.query(
                UserAnswer.normalized, db.func.count(UserAnswer.id)
            ).filter_by(quiz_id=quiz.id, question_id=q.id).group_by(UserAnswer.normalized).all()
            detail['freq'] = [{'answer': ans, 'count': cnt} for ans, cnt in freq]
        else:
            selected_ids = user_answers.get(q_id, [])
            detail['user_answer'] = selected_ids
            detail['correct'] = [opt.id for opt in q.options if opt.is_correct]
            detail['options'] = q.options
        details.append(detail)

    return render_template('result.html', result=result, quiz=quiz, details=details)

# ================== УДАЛЕНИЕ ВИКТОРИНЫ ==================
@app.route('/delete/<int:quiz_id>')
@login_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.creator_id != session['user_id']:
        flash('❌ Вы не можете удалить чужую викторину!', 'danger')
        return redirect(url_for('index'))

    try:
        UserAnswer.query.filter_by(quiz_id=quiz_id).delete()
        Result.query.filter_by(quiz_id=quiz_id).delete()
        db.session.delete(quiz)
        db.session.commit()
        flash('🗑 Викторина и все связанные данные удалены', 'info')
    except Exception as e:
        db.session.rollback()
        flash(f'❌ Ошибка: {str(e)}', 'danger')
    return redirect(url_for('index'))

# ================== УЧАСТНИКИ ПРИВАТНОЙ ВИКТОРИНЫ ==================
@app.route('/quiz/<int:quiz_id>/participants')
@login_required
def quiz_participants(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.creator_id != session['user_id'] or not quiz.is_private:
        flash('Нет доступа.', 'danger')
        return redirect(url_for('index'))

    results = Result.query.filter_by(quiz_id=quiz_id).order_by(Result.date.desc()).all()
    return render_template('participants.html', quiz=quiz, results=results)

# ================== ПРОФИЛЬ ==================
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        session['username'] = request.form.get('username', 'Гость').strip()
        return redirect(url_for('profile'))

    user = session['username']
    my_attempts = Result.query.filter_by(username=user).order_by(Result.date.desc()).all()
    my_quizzes = Quiz.query.filter_by(creator_id=session.get('user_id')).all()

    total_attempts = len(my_attempts)
    avg_correct = sum(r.score/r.total*100 for r in my_attempts)/total_attempts if total_attempts else 0

    created_stats = []
    for q in my_quizzes:
        attempts = q.results
        count = len(attempts)
        avg = sum(r.score/r.total*100 for r in attempts)/count if count else 0
        created_stats.append({'quiz': q, 'count': count, 'avg': round(avg, 1)})

    return render_template('profile.html',
                           user=user, attempts=my_attempts,
                           created=created_stats, total_attempts=total_attempts, avg_correct=round(avg_correct, 1))

# ================== ИНИЦИАЛИЗАЦИЯ ==================
def create_demo_data():
    if User.query.count() == 0:
        admin = User(username='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()
        q = Quiz(title="🐍 Основы Python", description="Проверка синтаксиса", is_private=False, creator_id=admin.id)
        db.session.add(q)
        db.session.flush()
        q1 = Question(quiz_id=q.id, text="Тип данных 42?")
        db.session.add(q1)
        db.session.flush()
        db.session.add_all([
            Option(question_id=q1.id, text="int", is_correct=True),
            Option(question_id=q1.id, text="str", is_correct=False)
        ])
        db.session.commit()

# Создание таблиц при импорте (сработает и при gunicorn)
with app.app_context():
    db.create_all()
    create_demo_data()
    @app.route('/health')
def health():
    return 'OK', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
