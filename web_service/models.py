from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()


# --------------------------------------------------
# ID 생성 함수
# --------------------------------------------------

def generate_next_id(connection, model, column_name, prefix):

    table = model.__table__
    column = getattr(table.c, column_name)

    result = connection.execute(
        db.select(column)
        .where(column.like(f"{prefix}-%"))
        .order_by(column.desc())
        .limit(1)
    ).first()

    if result is None:
        number = 1
    else:
        last_id = result[0]
        number = int(last_id.split("-")[1]) + 1

    return f"{prefix}-{number:06d}"


# --------------------------------------------------
# User
# --------------------------------------------------

class User(UserMixin, db.Model):

    __tablename__ = "users"

    user_id = db.Column(
        db.String(20),
        primary_key=True
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    # student / instructor
    user_type = db.Column(
        db.String(20),
        nullable=False
    )

    name = db.Column(
        db.String(50),
        nullable=False
    )

    birth_date = db.Column(
        db.String(10),
        nullable=False
    )

    phone = db.Column(
        db.String(20),
        nullable=False
    )

    pw_question = db.Column(
        db.String(255),
        nullable=False
    )

    pw_answer = db.Column(
        db.String(255),
        nullable=False
    )

    # 학생 성적
    student_grades = db.relationship(
        "Grade",
        foreign_keys="Grade.student_id",
        back_populates="student"
    )

    # 강사가 부여한 성적
    instructor_grades = db.relationship(
        "Grade",
        foreign_keys="Grade.instructor_id",
        back_populates="instructor"
    )

    # 학생이 작성한 문의글
    inquiries = db.relationship(
        "Inquiry",
        back_populates="student",
        cascade="all, delete-orphan"
    )

    # 댓글
    comments = db.relationship(
        "Comment",
        back_populates="author"
    )

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(
            self.password,
            password
        )
    def get_id(self):
        return self.user_id


# --------------------------------------------------
# Subject
# --------------------------------------------------

class Subject(db.Model):

    __tablename__ = "subjects"

    subject_id = db.Column(
        db.String(20),
        primary_key=True
    )

    subject_name = db.Column(
        db.String(100),
        nullable=False
    )

    instructor_id = db.Column(
        db.String(20),
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    # 담당 강사
    instructor = db.relationship(
        "User",
        foreign_keys=[instructor_id]
    )



# --------------------------------------------------
# Grade
# --------------------------------------------------

class Grade(db.Model):

    __tablename__ = "grades"

    grade_id = db.Column(
        db.String(20),
        primary_key=True
    )

    subject_id = db.Column(
        db.String(20),
        db.ForeignKey("subjects.subject_id"),
        nullable=False
    )

    instructor_id = db.Column(
        db.String(20),
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    student_id = db.Column(
        db.String(20),
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    score = db.Column(
        db.Integer,
        nullable=False
    )

    subject = db.relationship(
        "Subject",
        foreign_keys=[subject_id]
    )

    instructor = db.relationship(
        "User",
        foreign_keys=[instructor_id]
    )

    student = db.relationship(
        "User",
        foreign_keys=[student_id]
    )


# --------------------------------------------------
# Inquiry
# --------------------------------------------------

class Inquiry(db.Model):

    __tablename__ = "inquiries"

    inquiry_id = db.Column(
        db.String(20),
        primary_key=True
    )

    student_id = db.Column(
        db.String(20),
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    content = db.Column(
        db.Text,
        nullable=False
    )

    student = db.relationship(
        "User",
        back_populates="inquiries"
    )

    comments = db.relationship(
        "Comment",
        back_populates="inquiry",
        cascade="all, delete-orphan"
    )


# --------------------------------------------------
# Comment
# --------------------------------------------------

class Comment(db.Model):

    __tablename__ = "comments"

    comment_id = db.Column(
        db.String(20),
        primary_key=True
    )

    author_id = db.Column(
        db.String(20),
        db.ForeignKey("users.user_id"),
        nullable=False
    )

    inquiry_id = db.Column(
        db.String(20),
        db.ForeignKey("inquiries.inquiry_id"),
        nullable=False
    )

    content = db.Column(
        db.Text,
        nullable=False
    )

    author = db.relationship(
        "User",
        back_populates="comments"
    )

    inquiry = db.relationship(
        "Inquiry",
        back_populates="comments"
    )


# --------------------------------------------------
# ID 자동 생성
# --------------------------------------------------

@event.listens_for(User, "before_insert")
def generate_user_id(mapper, connection, target):

    if not target.user_id:

        if target.user_type == "student":
            prefix = "STU"
        elif target.user_type == "instructor":
            prefix = "INS"
        else:
            raise ValueError(
                "user_type은 student 또는 instructor여야 합니다."
            )

        target.user_id = generate_next_id(
            connection,
            User,
            "user_id",
            prefix
        )


@event.listens_for(Subject, "before_insert")
def generate_subject_id(mapper, connection, target):

    if not target.subject_id:

        target.subject_id = generate_next_id(
            connection,
            Subject,
            "subject_id",
            "SUB"
        )


@event.listens_for(Grade, "before_insert")
def generate_grade_id(mapper, connection, target):

    if not target.grade_id:

        target.grade_id = generate_next_id(
            connection,
            Grade,
            "grade_id",
            "GRD"
        )


@event.listens_for(Inquiry, "before_insert")
def generate_inquiry_id(mapper, connection, target):

    if not target.inquiry_id:

        target.inquiry_id = generate_next_id(
            connection,
            Inquiry,
            "inquiry_id",
            "QST"
        )


@event.listens_for(Comment, "before_insert")
def generate_comment_id(mapper, connection, target):

    if not target.comment_id:

        target.comment_id = generate_next_id(
            connection,
            Comment,
            "comment_id",
            "CMT"
        )