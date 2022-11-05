from flask import Flask, render_template,request,session
import ibm_db
import re
app=Flask(_name_,template_folder='template')
app.secret_key="a"
conn=ibm_db.connect("DATABASE=bludb;HOSTNAME=ba99a9e6-d59e-4883-8fc0-d6a8c9f7a08f.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT=31321;SECURITY=SSL;SSLServerCERTIFICATE=cert.crt;UID=jlt31380;PWD=X4pHXckP84xNczV4;",'','')
@app.route("/")
def home():
    return render_template('signup.html')
@app.route('/login',methods=["POST"])
def login():
    if request.method =="POST":
        UName=request.form['UName']
        UPass=request.form['UPass']
        sql="SELECT * FROM AUsers WHERE UName = ? AND UPass = ?"
        stmt=ibm_db.prepare(conn,sql)
        ibm_db.bind_param(stmt,1,UName)
        ibm_db.bind_param(stmt,2,UPass)
        ibm_db.execute(stmt)
        account=ibm_db.fetch_assoc(stmt)
        if account:
            session['Loggedin']=True
            # session['id']=account['id']
            session['UNAME']=account['UNAME']
            Msg="Welcome !!! \n Logged in successfully !"
            return render_template('welcome.html',Msg=Msg,UName=UName)
        else:
            Msg="Incorrect Password/Username"
            return render_template('login.html',Msg=Msg)

@app.route('/register/',methods=['POST','GET'])
def register():
    Msg=''
    if request.method=='POST':
        UName=request.form['UName']
        UMail=request.form['UMail']
        UPass=request.form['UPass']
        sql="SELECT * FROM AUsers WHERE UName = ?"
        stmt=ibm_db.prepare(conn,sql)
        ibm_db.bind_param(stmt,1,UName)
        ibm_db.execute(stmt)
        account=ibm_db.fetch_assoc(stmt)
        print(account)
        if account:
            Msg="The Account already Exists"
            
        elif not re.match(r'[^@]+@[^@]+\.[^@]+',UMail):
            Msg="Invalid Email Address"
            
        elif not re.match(r'[A-Za-z0-9]+',UName):
            Msg="Name must contain Characters and Numbers"
        else:
            insert_sql="INSERT INTO AUsers VALUES(?,?,?)"
            prep_stmt=ibm_db.prepare(conn,insert_sql)
            ibm_db.bind_param(prep_stmt,1,UName)
            ibm_db.bind_param(prep_stmt,2,UMail)
            ibm_db.bind_param(prep_stmt,3,UPass)
            ibm_db.execute(prep_stmt)
            Msg="Registered Successfully"
            return render_template('login.html',Msg=Msg)
    elif request.method=='POST':
        Msg="Please Fill the Form"
    return render_template('signup.html',Msg=Msg)

if _name=="main_":
    app.run(debug=True)
