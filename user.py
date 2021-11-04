from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class User:
    def __init__ (self, db_data):
        self.id = db_data['id']
        self.first_name = db_data['first_name']
        self.last_name = db_data['last_name']
        self.email = db_data['email']
        self.password = db_data['password']
        self.confirm_pass = db_data['confirm_pass']

    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        results = connectToMySQL('login_registration_schema').query_db(query)
        users = []
        for user in results:
            users.append( cls(user) )
        return users

    @classmethod
    def save(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password, confirm_pass) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, %(confirm_pass)s);"
        return connectToMySQL('login_registration_schema').query_db(query, data)
    
    @staticmethod
    def validate_login(user):
        is_valid = True
        if not EMAIL_REGEX.match(user['email']): 
            flash("Email address is required")
            is_valid = False
        return is_valid

    @staticmethod
    def validate_user_reg(user):
        is_valid = True
        if len(user['first_name']) < 2:
            flash("First name must be at least 2 characters.")
            is_valid = False
        if len(user['last_name']) < 2:
            flash("Last name must be at least 2 characters.")
            is_valid = False
        if not EMAIL_REGEX.match(user['email']): 
            flash("Invalid email address!")
            is_valid = False
        if len(user['password']) < 8:
            flash("Password must be at least 8 characters.")
            is_valid = False
        if len(user['confirm_pass']) < 8:
            flash("Password must be at least 8 characters.")
            is_valid = False
        if user['password'] != user['confirm_pass']:
            is_valid = False
            flash("Your passwords do not match")
        return is_valid

    @classmethod
    def get_by_email(cls, data):
        query = "SELECT * FROM users WHERE email = %(email)s"
        results = connectToMySQL('login_registration_schema').query_db(query, data)
        if len(results) == 0:
            return False
        return cls(results[0])
    
    @classmethod
    def get_by_id(cls, data):
        query = "SELECT * FROM users WHERE id = %(id)s"
        results = connectToMySQL('login_registration_schema').query_db(query, data)
        if len(results) == 0:
            return False
        return cls(results[0])

