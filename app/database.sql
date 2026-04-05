DROP DATABASE IF EXISTS should_i;
CREATE DATABASE should_i;
USE should_i;
DROP TABLE IF EXISTS User;
CREATE TABLE User (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    username VARCHAR(100) NOT NULL,
    password VARCHAR(100) NOT NULL,
    email TEXT NOT NULL,
    school TEXT NOT NULL,
    address TEXT NOT NULL,
    degree TEXT NOT NULL,
    year INTEGER NOT NULL
);

DROP TABLE IF EXISTS Course;
CREATE TABLE Course (
    user_id INTEGER REFERENCES User(id),
    course_code CHAR(4) NOT NULL,
    course_number INTEGER NOT NULL,
    seriousness CHAR(4)
);
