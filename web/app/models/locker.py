import pytz
from app import db
from datetime import datetime
from sqlalchemy_serializer import SerializerMixin

class Locker(db.Model, SerializerMixin):
    __tablename__ = "locker"

    id = db.Column(db.Integer, primary_key=True)
    stat_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    locker_id = db.Column(db.Integer)
    user_id = db.Column(db.Integer)
    timezone = db.Column(db.String(50))

    def __init__(self, stat_date, end_date, locker_id, user_id, timezone):
        self.stat_date = stat_date
        self.end_date = end_date
        self.locker_id = locker_id
        self.user_id = user_id
        self.timezone = timezone

    def update(self, stat_date, end_date, locker_id, user_id, timezone):
        self.stat_date = stat_date
        self.end_date = end_date
        self.locker_id = locker_id
        self.user_id = user_id
        self.timezone = timezone
