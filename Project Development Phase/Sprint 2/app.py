from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json as j
import ibm_db
import bcrypt
from functools import partial
import pyproj
from shapely.ops import transform
from shapely.geometry import Point

proj_wgs84 = pyproj.Proj('+proj=longlat +datum=WGS84')

try:
    conn = ibm_db.connect("DATABASE=bludb;HOSTNAME = ba99a9e6 - d59e - 4883 - 8fc0 - d6a8c9f7a08f.c1ogj3sd0tgtu0lqde00.databases.appdomain.cloud;PORT = 31321;SECURITY = SSL;SSLServerCertificate = cert.crt;PROTOCOL = TCPIP;UID = jlt31380;PWD = WXASMtoQ1r7dAYIB",'','')
    print(conn)
    print("connection successfull")
except:
    print("Error in connection, sqlstate = ")
    errorState = ibm_db.conn_error()
    print(errorState)
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


# HOME
@app.route("/", methods=['GET'])
def home():
    # if 'email' not in session:
    # return redirect(url_for('login'))
    return render_template('home.html', name='Home')


@app.route("/")
# USER REGISTER
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        stemp = str(request.data)
        stemp = stemp[2:len(stemp) - 1]
        stemp = stemp.replace("'", '"')
        data = j.loads(stemp)
        name = data['name']
        email = data['email']
        password = data['pass']
        cpassword = data['cpass']

        if not email or not name or not password or not cpassword:
            return 'Please fill all fields'
        if password != cpassword:
            return 'The password is not same'
        else:
            hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        query = "SELECT * FROM userlogin WHERE useremail=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)

        if not isUser:
            insert_sql = "INSERT INTO userlogin(USERNAME, USEREMAIL, PASSWORD) VALUES (?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, name)
            ibm_db.bind_param(prep_stmt, 2, email)
            ibm_db.bind_param(prep_stmt, 3, hash)
            ibm_db.execute(prep_stmt)
            return "You can login"
        else:
            return 'Invalid Credentials'

    return render_template('register.html')


# USER LOGIN
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        stemp = str(request.data)
        print(stemp)
        stemp = stemp[2:len(stemp) - 1]
        stemp = stemp.replace("'", '"')
        data = j.loads(stemp)
        email = data['email']
        password = data['pass']
        print(email, password)
        if not email or not password:
            return 'PLEASE FILL ALL FIELDS'
        query = "SELECT * FROM userlogin WHERE useremail=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)
        print(isUser, password)

        if not isUser:
            return "Invalid Username"
            # return render_template('login.html', error='INVALID USERNAME OR PASSWORD')
        # return render_template('login.html',error=isUser['PASSWORD'])

        isPasswordMatch = False
        temp = str(isUser['PASSWORD'])
        temp = temp.replace("\x00", '')
        temp = temp[2:len(temp) - 1]
        temp = temp.encode("utf-8")
        check = bcrypt.hashpw(password.encode('utf-8'), temp)
        # print(check==temp[:len(check)])
        if check == temp[:len(check)]:
            isPasswordMatch = True
        # isPasswordMatch = bcrypt.checkpw(password.encode('utf-8'), isUser['PASSWORD'])

        if not isPasswordMatch:
            return "Invalid Credentials"
            # return render_template('login.html', error='Invalid Credentials')

        session['email'] = isUser['USEREMAIL']
        return "valid"
    return render_template('login.html', name='Home')


# ADMIN REGISTER
@app.route("/add_reg", methods=['GET', 'POST'])
def add_reg():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        cpassword = request.form['cpassword']

        if not email or not name or not password or not cpassword:
            return render_template('add_reg.html', error='Please fill all fields')
        if password != cpassword:
            return render_template('add_reg.html', error='The password is not same')
        else:
            hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            print(type(hash))
            print(hash)
            # encpass=hash.decode()
            # print(encpass)
            # print(type(encpass))

        query = "SELECT * FROM ADMIN WHERE useremail=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)
        ibm_db.execute(stmt)
        isUser = ibm_db.fetch_assoc(stmt)

        if not isUser:
            insert_sql = "INSERT INTO ADMIN(USERNAME, USEREMAIL, PASSWORD) VALUES (?,?,?)"
            prep_stmt = ibm_db.prepare(conn, insert_sql)
            ibm_db.bind_param(prep_stmt, 1, name)
            ibm_db.bind_param(prep_stmt, 2, email)
            ibm_db.bind_param(prep_stmt, 3, hash)
            ibm_db.execute(prep_stmt)
            return render_template('add_reg.html', success="You can login")
        else:
            return render_template('add_reg.html', error='Invalid Credentials')
    else:
        return render_template('add_reg.html')


# ADMIN LOGIN
@app.route("/add_log", methods=['GET', 'POST'])
def add_log():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if not email or not password:
            return render_template('add_log.html', error='PLEASE FILL ALL FIELDS')

        query = "SELECT * FROM ADMIN WHERE useremail=?"
        stmt = ibm_db.prepare(conn, query)
        ibm_db.bind_param(stmt, 1, email)

        ibm_db.execute(stmt)
        isAdmin = ibm_db.fetch_assoc(stmt)
        print(isAdmin, password)

        if not isAdmin:
            return render_template('add_log.html', error='INVALID USERNAME OR PASSWORD')
        # return render_template('login.html',error=isUser['PASSWORD'])

        isPasswordMatch = False
        temp = str(isAdmin['PASSWORD'])
        temp = temp.replace("\x00", '')
        temp = temp[2:len(temp) - 1]
        print(temp)
        temp = temp.encode("utf-8")
        print(temp, type(temp))
        check = bcrypt.hashpw(password.encode('utf-8'), temp)
        # print(check==temp[:len(check)])
        if check == temp[:len(check)]:
            isPasswordMatch = True
        # isPasswordMatch = bcrypt.checkpw(password.encode('utf-8'), isUser['PASSWORD'])

        if not isPasswordMatch:
            return render_template('add_log.html', error='Invalid Credentials')

        session['email'] = isAdmin['USEREMAIL']
        return redirect(url_for('addzone'))

    return render_template('add_log.html', name='Home')


# ADD ZONE
@app.route("/addzone", methods=['GET', 'POST'])
def addzone():
    if request.method == 'POST':
        latitude = request.form['latitude']
        longitude = request.form['longitude']

        if not latitude or not longitude:
            return render_template('addzone.html', msg='Please fill all fields')
        sql = "INSERT INTO ADDZONE(LATITUDE,LONGITUDE) VALUES(?,?)"
        stmt = ibm_db.prepare(conn, sql)
        ibm_db.bind_param(stmt, 1, latitude)
        ibm_db.bind_param(stmt, 2, longitude)
        ibm_db.execute(stmt)
        return render_template('addzone.html', msg='zone added sucessfully')
    else:
        return render_template('addzone.html')


# Check ZONE
@app.route('/checkzone', methods=['GET', 'POST'])
def checkzone():
    if request.method == 'POST':
        stemp = str(request.data)
        stemp = stemp[2:len(stemp) - 1]
        stemp = stemp.replace("'", '"')
        data = j.loads(stemp)
        ulat = float(data['lat'])
        ulon = float(data['lon'])
        query = "SELECT * FROM ADDZONE"
        stmt = ibm_db.exec_immediate(conn, query)
        tuple = ibm_db.fetch_tuple(stmt)
        anslat = []
        anslon = []
        alat = []
        alon = []
        while tuple != False:
            lat = tuple[0]
            lon = tuple[1]
            km = 10
            # Azimuthal equidistant projection
            aeqd_proj = '+proj=aeqd +lat_0={lat} +lon_0={lon} +x_0=0 +y_0=0'
            project = partial(
                pyproj.transform,
                pyproj.Proj(aeqd_proj.format(lat=lat, lon=lon)),
                proj_wgs84)
            buf = Point(0, 0).buffer(km * 1000)  # distance in metres
            b = transform(project, buf).exterior.coords[:]
            for i in b:
                alat.append(i[0])
                alon.append(i[1])
            anslon.append([min(alat), max(alat)])
            anslat.append([min(alon), max(alon)])
            tuple = ibm_db.fetch_tuple(stmt)
        print(anslat, anslon)
        print(ulat, ulon)
        for i in range(len(anslat)):
            # print(ulat,anslat[i][0],ulat,anslat[i][1],ulat,anslon[i][0],ulat,anslon[i][1])
            if ((ulat >= anslat[i][0]) and (ulat <= anslat[i][1]) and (ulon >= anslon[i][0]) and (
                    ulon <= anslon[i][1])):
                return "inside"

        return 'outside'
    else:
        return render_template('addzone.html')


@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
