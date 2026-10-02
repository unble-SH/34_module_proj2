from flask import (
    Flask,
    flash,
    render_template,
    redirect,
    url_for,
    request
)

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from config import Config

from models import (
    db,
    User,
    Subject,
    Grade,
    Inquiry,
    Comment
)


# --------------------------------------------------
# Flask 설정
# --------------------------------------------------

app = Flask(__name__)
app.config.from_object(Config)


# --------------------------------------------------
# Database
# --------------------------------------------------

db.init_app(app)


# --------------------------------------------------
# Flask-Login
# --------------------------------------------------

login_manager = LoginManager()

login_manager.init_app(app)

# 로그인하지 않은 사용자가 접근했을 때
# 이동할 페이지
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(user_id)


# --------------------------------------------------
# 초기 데이터
# --------------------------------------------------

def initialize_data():

    existing_instructor = User.query.filter_by(
        username="instructor"
    ).first()

    if existing_instructor:
        return

    # ----------------------------------------
    # 강사
    # ----------------------------------------

    instructor = User(
        username="instructor",
        user_type="instructor",
        name="김강사",
        birth_date="1985-01-01",
        phone="010-1111-1111",
        pw_question="가장 좋아하는 과목은?",
        pw_answer="Python"
    )

    instructor.set_password("instructor123")

    db.session.add(instructor)
    db.session.flush()

    # ----------------------------------------
    # 학생
    # ----------------------------------------

    students = []

    student_data = [
        ("student1", "홍길동", "2003-03-01", "010-2000-0001", 85),
        ("student2", "김철수", "2003-05-12", "010-2000-0002", 92),
        ("student3", "이영희", "2004-01-20", "010-2000-0003", 78),
        ("student4", "박민수", "2003-11-03", "010-2000-0004", 95),
        ("student5", "최지우", "2004-07-15", "010-2000-0005", 88),
    ]

    for username, name, birth_date, phone, score in student_data:

        student = User(
            username=username,
            user_type="student",
            name=name,
            birth_date=birth_date,
            phone=phone,
            pw_question="가장 좋아하는 음식은?",
            pw_answer="김치찌개"
        )

        student.set_password("student123")

        db.session.add(student)
        db.session.flush()

        students.append(
            (student, score)
        )

    # ----------------------------------------
    # Python 과목
    # ----------------------------------------

    python_subject = Subject(
        subject_name="Python",
        instructor_id=instructor.user_id
    )

    db.session.add(python_subject)
    db.session.flush()

    # ----------------------------------------
    # 성적
    # ----------------------------------------

    for student, score in students:

        grade = Grade(
            subject_id=python_subject.subject_id,
            instructor_id=instructor.user_id,
            student_id=student.user_id,
            score=score
        )

        db.session.add(grade)
        db.session.flush()

    db.session.commit()

    print("기본 데이터 생성 완료")


# --------------------------------------------------
# Root
# --------------------------------------------------

@app.route("/")
def index():

    # 로그인하지 않았다면 로그인 페이지로
    if not current_user.is_authenticated:
        return redirect(url_for("login"))

    # 학생
    if current_user.user_type == "student":
        return redirect(url_for("student_home"))

    # 강사
    if current_user.user_type == "instructor":
        return redirect(url_for("instructor_home"))

    # 혹시 알 수 없는 user_type이면 로그아웃
    logout_user()

    return redirect(url_for("login"))


# --------------------------------------------------
# Login
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    # 이미 로그인한 상태라면 /
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(
            username=username
        ).first()

        if user and user.check_password(password):

            login_user(user)

            return redirect(url_for("index"))

        return render_template(
            "login.html",
            error="아이디 또는 비밀번호가 올바르지 않습니다."
        )

    return render_template("login.html")


# --------------------------------------------------
# Logout
# --------------------------------------------------

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))


# ==================================================
# 학생
# ==================================================

@app.route("/student")
@login_required
def student_home():

    if current_user.user_type != "student":
        return redirect(url_for("index"))

    return render_template(
        "student/home.html"
    )


@app.route("/student/mypage")
@login_required
def student_mypage():

    if current_user.user_type != "student":
        return redirect(url_for("index"))

    return render_template(
        "student/mypage.html",
        user=current_user
    )


@app.route("/student/profile", methods=["GET", "POST"])
@login_required
def student_profile():

    if current_user.user_type != "student":
        return redirect(url_for("index"))

    if request.method == "POST":

        name = request.form.get("name")
        birth_date = request.form.get("birth_date")
        phone = request.form.get("phone")

        # 필수값 확인
        if not name or not birth_date or not phone:

            return render_template(
                "student/profile.html",
                user=current_user,
                error="모든 항목을 입력해주세요."
            )

        # 사용자 정보 수정
        current_user.name = name
        current_user.birth_date = birth_date
        current_user.phone = phone

        try:

            db.session.commit()

        except Exception:

            db.session.rollback()

            return render_template(
                "student/profile.html",
                user=current_user,
                error="개인정보 수정 중 오류가 발생했습니다."
            )

        return redirect(
            url_for("student_mypage")
        )

    return render_template(
        "student/profile.html",
        user=current_user
    )


@app.route("/student/grades")
@login_required
def student_grades():

    if current_user.user_type != "student":
        return redirect(url_for("index"))

    grades = Grade.query.filter_by(
        student_id=current_user.user_id
    ).all()

    return render_template(
        "student/grades.html",
        grades=grades
    )


@app.route("/student/inquiries")
@login_required
def student_inquiries():

    if current_user.user_type != "student":
        return redirect(url_for("index"))

    inquiries = Inquiry.query.filter_by(
        student_id=current_user.user_id
    ).all()

    return render_template(
        "student/inquiries.html",
        inquiries=inquiries
    )

@app.route("/student/inquiries/write", methods=["GET", "POST"])
@login_required
def student_inquiry_write():

    if current_user.user_type != "student":
        return redirect(url_for("index"))

    if request.method == "POST":

        content = request.form.get("content")

        if not content or not content.strip():

            return render_template(
                "student/inquiry_write.html",
                error="문의 내용을 입력해주세요."
            )

        inquiry = Inquiry(
            student_id=current_user.user_id,
            content=content.strip()
        )

        db.session.add(inquiry)

        try:

            db.session.flush()
            db.session.commit()

        except Exception:

            db.session.rollback()

            return render_template(
                "student/inquiry_write.html",
                error="문의글 작성 중 오류가 발생했습니다."
            )

        return redirect(
            url_for("student_inquiries")
        )

    return render_template(
        "student/inquiry_write.html"
    )

# ==================================================
# 강사
# ==================================================

@app.route("/instructor")
@login_required
def instructor_home():

    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    return render_template(
        "instructor/home.html"
    )


@app.route("/instructor/students")
@login_required
def instructor_students():

    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    students = User.query.filter_by(
        user_type="student"
    ).all()

    return render_template(
        "instructor/students.html",
        students=students
    )


@app.route("/instructor/grades", methods=["GET", "POST"])
@login_required
def instructor_grades():

    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    # ----------------------------------------
    # POST - 성적 등록
    # ----------------------------------------

    if request.method == "POST":

        subject_id = request.form.get("subject_id")
        student_id = request.form.get("student_id")
        score = request.form.get("score")

        # 입력값 확인
        if not subject_id or not student_id or score == "":
            return redirect(
                url_for("instructor_grades")
            )

        # 점수 숫자 확인
        try:
            score = int(score)

        except ValueError:

            return render_template(
                "instructor/grades.html",
                subjects=get_instructor_subjects(),
                students=get_students(),
                grades=get_instructor_grades(),
                error="점수는 숫자로 입력해주세요."
            )

        # 점수 범위
        if score < 0 or score > 100:

            return render_template(
                "instructor/grades.html",
                subjects=get_instructor_subjects(),
                students=get_students(),
                grades=get_instructor_grades(),
                error="점수는 0~100 사이로 입력해주세요."
            )

        # ----------------------------------------
        # 과목 확인
        # ----------------------------------------

        subject = Subject.query.filter_by(
            subject_id=subject_id,
            instructor_id=current_user.user_id
        ).first()

        if not subject:

            return render_template(
                "instructor/grades.html",
                subjects=get_instructor_subjects(),
                students=get_students(),
                grades=get_instructor_grades(),
                error="해당 과목에 접근할 수 없습니다."
            )

        # ----------------------------------------
        # 학생 확인
        # ----------------------------------------

        student = User.query.filter_by(
            user_id=student_id,
            user_type="student"
        ).first()

        if not student:

            return render_template(
                "instructor/grades.html",
                subjects=get_instructor_subjects(),
                students=get_students(),
                grades=get_instructor_grades(),
                error="존재하지 않는 학생입니다."
            )

        # ----------------------------------------
        # 기존 성적 확인
        # ----------------------------------------

        grade = Grade.query.filter_by(
            subject_id=subject_id,
            student_id=student_id
        ).first()

        if grade:

            # 기존 성적이 있으면 수정
            grade.score = score

        else:

            # 없으면 새로 생성
            grade = Grade(
                subject_id=subject_id,
                instructor_id=current_user.user_id,
                student_id=student_id,
                score=score
            )

            db.session.add(grade)

        try:

            db.session.flush()
            db.session.commit()

        except Exception:

            db.session.rollback()

            return render_template(
                "instructor/grades.html",
                subjects=get_instructor_subjects(),
                students=get_students(),
                grades=get_instructor_grades(),
                error="성적 저장 중 오류가 발생했습니다."
            )

        return redirect(
            url_for("instructor_grades")
        )

    # ----------------------------------------
    # GET
    # ----------------------------------------

    return render_template(
        "instructor/grades.html",
        subjects=get_instructor_subjects(),
        students=get_students(),
        grades=get_instructor_grades()
    )


@app.route("/instructor/inquiries")
@login_required
def instructor_inquiries():

    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    inquiries = Inquiry.query.all()

    return render_template(
        "instructor/inquiries.html",
        inquiries=inquiries
    )

@app.route("/instructor/mypage")
@login_required
def instructor_mypage():

    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    return render_template(
        "instructor/mypage.html",
        user=current_user
    )


@app.route("/instructor/profile", methods=["GET", "POST"])
@login_required
def instructor_profile():

    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    if request.method == "POST":

        name = request.form.get("name")
        birth_date = request.form.get("birth_date")
        phone = request.form.get("phone")

        if not name or not birth_date or not phone:

            return render_template(
                "instructor/profile.html",
                user=current_user,
                error="모든 항목을 입력해주세요."
            )

        current_user.name = name
        current_user.birth_date = birth_date
        current_user.phone = phone

        try:

            db.session.commit()

        except Exception:

            db.session.rollback()

            return render_template(
                "instructor/profile.html",
                user=current_user,
                error="개인정보 수정 중 오류가 발생했습니다."
            )

        return redirect(
            url_for("instructor_mypage")
        )

    return render_template(
        "instructor/profile.html",
        user=current_user
    )

@app.route("/instructor/subjects", methods=["GET", "POST"])
@login_required
def instructor_subjects():

    # 강사만 접근 가능
    if current_user.user_type != "instructor":
        return redirect(url_for("index"))

    if request.method == "POST":

        subject_name = request.form.get("subject_name")

        if not subject_name:
            return render_template(
                "instructor/subjects.html",
                error="과목명을 입력해주세요.",
                subjects=Subject.query.filter_by(
                    instructor_id=current_user.user_id
                ).all()
            )

        # 같은 강사가 동일한 과목을 중복 등록하는 것을 방지
        existing_subject = Subject.query.filter_by(
            subject_name=subject_name,
            instructor_id=current_user.user_id
        ).first()

        if existing_subject:

            return render_template(
                "instructor/subjects.html",
                error="이미 등록한 과목입니다.",
                subjects=Subject.query.filter_by(
                    instructor_id=current_user.user_id
                ).all()
            )

        subject = Subject(
            subject_name=subject_name,
            instructor_id=current_user.user_id
        )

        db.session.add(subject)

        try:
            db.session.flush()
            db.session.commit()

        except Exception:

            db.session.rollback()

            return render_template(
                "instructor/subjects.html",
                error="과목 추가 중 오류가 발생했습니다.",
                subjects=Subject.query.filter_by(
                    instructor_id=current_user.user_id
                ).all()
            )

        return redirect(
            url_for("instructor_subjects")
        )

    subjects = Subject.query.filter_by(
        instructor_id=current_user.user_id
    ).all()

    return render_template(
        "instructor/subjects.html",
        subjects=subjects
    )

# --------------------------------------------------
# 회원가입
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    # 이미 로그인한 사용자는 회원가입 페이지에 접근하지 않음
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":

        # -----------------------------
        # 입력값 가져오기
        # -----------------------------

        user_type = request.form.get("user_type")
        username = request.form.get("username")
        password = request.form.get("password")
        password_confirm = request.form.get("password_confirm")

        name = request.form.get("name")
        birth_date = request.form.get("birth_date")
        phone = request.form.get("phone")

        pw_question = request.form.get("pw_question")
        pw_answer = request.form.get("pw_answer")

        # -----------------------------
        # 필수값 검사
        # -----------------------------

        if not all([
            user_type,
            username,
            password,
            password_confirm,
            name,
            birth_date,
            phone,
            pw_question,
            pw_answer
        ]):
            return render_template(
                "register.html",
                error="모든 항목을 입력해주세요."
            )

        # -----------------------------
        # 회원 유형 검사
        # -----------------------------

        if user_type not in ["student", "instructor"]:
            return render_template(
                "register.html",
                error="올바른 회원 유형을 선택해주세요."
            )

        # -----------------------------
        # 비밀번호 확인
        # -----------------------------

        if password != password_confirm:
            return render_template(
                "register.html",
                error="비밀번호가 일치하지 않습니다."
            )

        # -----------------------------
        # 아이디 중복 확인
        # -----------------------------

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:
            return render_template(
                "register.html",
                error="이미 사용 중인 아이디입니다."
            )

        # -----------------------------
        # 사용자 생성
        # -----------------------------

        user = User(
            username=username,
            user_type=user_type,
            name=name,
            birth_date=birth_date,
            phone=phone,
            pw_question=pw_question,
            pw_answer=pw_answer
        )

        # 비밀번호는 평문으로 저장하지 않음
        user.set_password(password)

        db.session.add(user)

        try:
            # user_id 생성
            db.session.flush()

            # 최종 저장
            db.session.commit()

        except Exception:
            db.session.rollback()

            return render_template(
                "register.html",
                error="회원가입 중 오류가 발생했습니다."
            )

        return redirect(url_for("login"))

    return render_template("register.html")

def get_instructor_subjects():

    return Subject.query.filter_by(
        instructor_id=current_user.user_id
    ).all()


def get_students():

    return User.query.filter_by(
        user_type="student"
    ).all()


def get_instructor_grades():

    return Grade.query.join(
        Subject,
        Grade.subject_id == Subject.subject_id
    ).filter(
        Subject.instructor_id == current_user.user_id
    ).all()

# --------------------------------------------------
# 문의글
# --------------------------------------------------
@app.route("/inquiries/<inquiry_id>")
@login_required
def inquiry_detail(inquiry_id):

    inquiry = Inquiry.query.filter_by(
        inquiry_id=inquiry_id
    ).first_or_404()

    # if current_user.user_type == "student":

    #     if inquiry.student_id != current_user.user_id:
    #         return redirect(
    #             url_for("student_inquiries")
    #         )

    # elif current_user.user_type == "instructor":
    #     pass

    # else:
    #     return redirect(url_for("index"))

    return render_template(
        "inquiry_detail.html",
        inquiry=inquiry
    )

@app.route(
    "/inquiries/<inquiry_id>/comment",
    methods=["POST"]
)
@login_required
def add_comment(inquiry_id):

    inquiry = Inquiry.query.filter_by(
        inquiry_id=inquiry_id
    ).first_or_404()

    # ---------------------------------
    # 접근 권한 확인
    # ---------------------------------

    # if current_user.user_type == "student":

    #     # 자신의 문의글에만 댓글 가능
    #     if inquiry.student_id != current_user.user_id:

    #         return redirect(
    #             url_for("student_inquiries")
    #         )

    # elif current_user.user_type == "instructor":

    #     # 강사는 모든 문의글에 댓글 가능
    #     pass

    # else:

    #     return redirect(
    #         url_for("index")
    #     )

    content = request.form.get("content")

    if not content or not content.strip():

        return redirect(
            url_for(
                "inquiry_detail",
                inquiry_id=inquiry_id
            )
        )

    comment = Comment(
        author_id=current_user.user_id,
        inquiry_id=inquiry.inquiry_id,
        content=content.strip()
        )

    db.session.add(comment)

    try:

        db.session.flush()
        db.session.commit()

    except Exception:

        db.session.rollback()

    return redirect(
        url_for(
            "inquiry_detail",
            inquiry_id=inquiry_id
        )
    )
# --------------------------------------------------
# 비밀번호 재설정
# --------------------------------------------------

@app.route('/find_password', methods=['GET', 'POST'])
def find_password():
    error = None
    found_password = None

    if request.method == 'POST':
        username = request.form.get('username')
        pw_question = request.form.get('pw_question')
        pw_answer = request.form.get('pw_answer')

        user = User.query.filter_by(username=username).first()

        # 보안 질문 및 답변 검증
        if user and user.pw_question == pw_question and user.pw_answer == pw_answer:
            # 취약점 진단 시나리오:
            # 1. 고정/단순 패턴("temp1234!")으로 패스워드 강제 변경
            # 2. 웹 브라우저 화면에 재설정된 비밀번호 즉시 노출 (취약 판정 기준)
            new_password = "temp1234!"
            user.set_password(new_password)
            db.session.commit()
            
            found_password = new_password
        else:
            error = "입력하신 정보와 일치하는 계정이 없거나 답변이 올바르지 않습니다."

    return render_template('find_password.html', error=error, found_password=found_password)


# --------------------------------------------------
# 실행
# --------------------------------------------------

with app.app_context():

    db.create_all()

    initialize_data()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )