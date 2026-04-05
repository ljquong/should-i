from fastapi import FastApi
import mysql.connector


app = FastApi()
conn = mysql.connector.connect(
    host = "localhost",
    user = "root",
    password = "Punar_19"
)

cursor = conn.cursor()

@app.post("/register")
def register(first_name:str, last_name:str, courses: str, year:int, home_address:str, course_num:int, email:str):
    sql = "INSERT INTO user()"
    values = ""

    cursor.execute(sql,values)
    conn.commit()


@app.post("/token")



