#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

import os
import sqlite3
import xmlrpc.client
import configparser
from datetime import datetime, timedelta
import xmlrpc.client
import logging
from flask import Flask, render_template, url_for, redirect, jsonify, request, g, session

CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../cesi.conf"))
print(CONFIG_FILE)


class Config(object):
    def __init__(self, file):
        self.file = file
        self.cfg = configparser.ConfigParser()
        self.cfg.read(self.file)

        self.node_list = []
        for name in self.cfg.sections():
            if name[:4] == 'node':
                self.node_list.append(name[5:])

        self.environment_list = []
        for name in self.cfg.sections():
            if name[:11] == 'environment':
                self.environment_list.append(name[12:])

        self.group_list = []
        for name in self.cfg.sections():
            if name[:5] == 'group':
                self.group_list.append(name[6:])

    def node(self, node_name):
        node_name = "node:{0}".format(node_name)
        username = self.cfg.get(node_name, 'username')
        password = self.cfg.get(node_name, 'password')
        host = self.cfg.get(node_name, 'host')
        port = self.cfg.get(node_name, 'port')
        node_config = NodeConfig(node_name, host, port, username, password)
        return node_config

    def member_names(self, environment_name):
        environment_name = "environment:{0}".format(environment_name)
        member_list = self.cfg.get(environment_name, 'members').split(', ')
        return member_list

    def db(self):
        return self.cfg.get('cesi', 'database')

    def log(self):
        return self.cfg.get('cesi', 'activity_log', fallback=None)

    def host(self):
        return self.cfg.get('cesi', 'host')


_CONFIG = Config(CONFIG_FILE)


class NodeConfig:
    def __init__(self, node_name, host, port, username, password):
        self.node_name = node_name
        self.host = host
        self.port = port
        self.username = username
        self.password = password


class Node:
    def __init__(self, node_config):
        self.long_name = node_config.node_name
        self.name = node_config.node_name[5:]
        self.connection = Connection(node_config.host, node_config.port, node_config.username,
                                     node_config.password).get()
        self.process_list = []
        self.process_dict2 = {}
        for p in self.connection.supervisor.getAllProcessInfo():
            self.process_list.append(ProcessInfo(p))
            self.process_dict2[p['group'] + ':' + p['name']] = ProcessInfo(p)
        self.process_dict = self.connection.supervisor.getAllProcessInfo()


class Connection:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.address = "http://%s:%s@%s:%s/RPC2" % (self.username, self.password, self.host, self.port)

    def get(self):
        return xmlrpc.client.Server(self.address)


class ProcessInfo:
    def __init__(self, dictionary):
        self.dictionary = dictionary
        self.name = self.dictionary['name']
        self.group = self.dictionary['group']
        self.start = self.dictionary['start']
        self.start_hr = datetime.fromtimestamp(self.dictionary['start']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.stop_hr = datetime.fromtimestamp(self.dictionary['stop']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.now_hr = datetime.fromtimestamp(self.dictionary['now']).strftime('%Y-%m-%d %H:%M:%S')[11:]
        self.stop = self.dictionary['stop']
        self.now = self.dictionary['now']
        self.state = self.dictionary['state']
        self.statename = self.dictionary['statename']
        self.spawnerr = self.dictionary['spawnerr']
        self.exitstatus = self.dictionary['exitstatus']
        self.stdout_logfile = self.dictionary['stdout_logfile']
        self.stderr_logfile = self.dictionary['stderr_logfile']
        self.pid = self.dictionary['pid']
        self.seconds = self.now - self.start
        self.uptime = str(timedelta(seconds=self.seconds))


class JsonValue:
    def __init__(self, process_name, node_name, event):
        self.process_name = process_name
        self.event = event
        self.node_name = node_name
        self.node_config = _CONFIG.node(self.node_name)
        self.node = Node(self.node_config)

    def success(self):
        return jsonify(status="Success",
                       code=80,
                       message="%s %s %s event succesfully" % (self.node_name, self.process_name, self.event),
                       nodename=self.node_name,
                       data=self.node.connection.supervisor.getProcessInfo(self.process_name))

    def error(self, code, payload):
        return jsonify(status="Error",
                       code=code,
                       message="%s %s %s event unsuccesful" % (self.node_name, self.process_name, self.event),
                       nodename=self.node_name,
                       payload=payload)


app = Flask(__name__)
app.config.from_object(__name__)
app.secret_key = '42'

DATABASE = _CONFIG.db()
ACTIVITY_LOG = _CONFIG.log()
HOST = _CONFIG.host()

LOG = logging.getLogger(__name__)
_LOG_FMT = "[%(asctime)s][%(levelname)s][%(name)s] %(message)s"


# Database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db


# Close database connection
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


# Username and password control
@app.route('/login/control', methods=['GET', 'POST'])
def control():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        cur = get_db().cursor()
        cur.execute("SELECT * FROM userinfo WHERE username=?", (username,))
        # if query returns an empty list
        if not cur.fetchall():
            session.clear()

            LOG.info("Login fail. Username is not avaible.\n")
            return jsonify(status="warning",
                           message="Username is not  avaible ")
        else:
            cur.execute("SELECT * FROM userinfo WHERE username=?", (username,))
            if password == cur.fetchall()[0][1]:
                session['username'] = username
                session['logged_in'] = True
                cur.execute("SELECT * FROM userinfo WHERE username=?", (username,))
                session['usertype'] = cur.fetchall()[0][2]

                LOG.info("%s logged in.\n" % (session['username']))
                return jsonify(status="success")
            else:
                session.clear()

                LOG.info("Login fail. Invalid password.\n")
                return jsonify(status="warning",
                               message="Invalid password")


# Render login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


# Logout action
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    LOG.info("%s logged out.\n" % (session['username']))
    session.clear()
    return redirect(url_for('login'))


# Dashboard
@app.route('/')
def index():
    # get user type
    if session.get('logged_in'):
        if session['usertype'] == 0:
            usertype = "Admin"
        elif session['usertype'] == 1:
            usertype = "Standart User"
        elif session['usertype'] == 2:
            usertype = "Only Log"
        elif session['usertype'] == 3:
            usertype = "Read Only"

        all_process_count = 0
        running_process_count = 0
        stopped_process_count = 0
        member_names = []
        environment_list = []
        g_node_list = []
        g_process_list = []
        g_environment_list = []
        group_list = []
        not_connected_node_list = []
        connected_node_list = []

        node_name_list = _CONFIG.node_list
        node_count = len(node_name_list)
        environment_name_list = _CONFIG.environment_list

        for node_name in node_name_list:
            nodeconfig = _CONFIG.node(node_name)

            try:
                node = Node(nodeconfig)
                if node_name not in connected_node_list:
                    connected_node_list.append(node_name)
            except Exception as err:
                if node_name not in not_connected_node_list:
                    not_connected_node_list.append(node_name)
                continue

            for name in list(node.process_dict2.keys()):
                p_group = name.split(':')[0]
                p_name = name.split(':')[1]
                if p_group != p_name:
                    if p_group not in group_list:
                        group_list.append(p_group)

            for process in node.process_list:
                all_process_count += 1
                if process.state == 20:
                    running_process_count += 1
                if process.state == 0:
                    stopped_process_count += 1

        # get environment list 
        for env_name in environment_name_list:
            env_members = _CONFIG.member_names(env_name)
            for index, node in enumerate(env_members):
                if node not in connected_node_list:
                    env_members.pop(index)
            environment_list.append(env_members)

        for g_name in group_list:
            tmp = []
            for node_name in connected_node_list:
                nodeconfig = _CONFIG.node(node_name)
                node = Node(nodeconfig)
                for name in list(node.process_dict2.keys()):
                    group_name = name.split(':')[0]
                    if group_name == g_name:
                        if node_name not in tmp:
                            tmp.append(node_name)
            g_node_list.append(tmp)

        for sub_list in g_node_list:
            tmp = []
            for name in sub_list:
                for env_name in environment_name_list:
                    if name in _CONFIG.member_names(env_name):
                        if name in connected_node_list:
                            if env_name not in tmp:
                                tmp.append(env_name)
            g_environment_list.append(tmp)

        connected_count = len(connected_node_list)
        not_connected_count = len(not_connected_node_list)

        return render_template('index.html',
                               all_process_count=all_process_count,
                               running_process_count=running_process_count,
                               stopped_process_count=stopped_process_count,
                               node_count=node_count,
                               node_name_list=node_name_list,
                               connected_count=connected_count,
                               not_connected_count=not_connected_count,
                               environment_list=environment_list,
                               environment_name_list=environment_name_list,
                               group_list=group_list,
                               g_environment_list=g_environment_list,
                               connected_node_list=connected_node_list,
                               not_connected_node_list=not_connected_node_list,
                               username=session['username'],
                               usertype=usertype,
                               usertypecode=session['usertype'])
    else:
        return redirect(url_for('login'))


# Show node
@app.route('/node/<node_name>')
def show_node(node_name):
    if session.get('logged_in'):
        node_config = _CONFIG.node(node_name)
        LOG.info("%s viewed node %s .\n", session['username'], node_name)
        return jsonify(process_info=Node(node_config).process_dict)
    else:

        LOG.info("Illegal request for view node %s .\n", node_name)
        return redirect(url_for('login'))


@app.route('/group/<group_name>/environment/<environment_name>')
def show_group(group_name, environment_name):
    if session.get('logged_in'):
        env_member_list = _CONFIG.member_names(environment_name)
        process_list = []
        for node_name in env_member_list:
            node_config = _CONFIG.node(node_name)
            try:
                node = Node(node_config)
            except Exception as err:
                continue
            p_list = list(node.process_dict2.keys())
            for name in p_list:
                if name.split(':')[0] == group_name:
                    tmp = [
                        node.process_dict2[name].pid,
                        name.split(':')[1],
                        node_name,
                        node.process_dict2[name].uptime,
                        node.process_dict2[name].state,
                        node.process_dict2[name].statename,
                    ]
                    process_list.append(tmp)
        return jsonify(process_list=process_list)
    else:
        return redirect(url_for('login'))


@app.route('/node/<node_name>/process/<process_name>/restart')
def json_restart(node_name, process_name):
    if session.get('logged_in'):
        if session['usertype'] == 0 or session['usertype'] == 1:
            try:
                node_config = _CONFIG.node(node_name)
                node = Node(node_config)
                if node.connection.supervisor.stopProcess(process_name):
                    if node.connection.supervisor.startProcess(process_name):
                        LOG.info("%s restarted %s node's %s process .\n" % (
                            session['username'], node_name, process_name))
                        return JsonValue(process_name, node_name, "restart").success()
            except xmlrpc.client.Fault as err:

                LOG.info("%s unsucces restart event %s node's %s process .\n" % (
                    session['username'], node_name, process_name))
                return JsonValue(process_name, node_name, "restart").error(err.faultCode, err.faultString)
        else:

            LOG.info(
                "%s is unauthorized user request for restart. Restart event fail for %s node's %s process .\n" % (
                    session['username'], node_name, process_name))
            return jsonify(status="error2",
                           message="You are not authorized this action")
    else:

        LOG.info("Illegal request for restart to %s node's process %s .\n" % (node_name, process_name))
        return redirect(url_for('login'))


# Process start
@app.route('/node/<node_name>/process/<process_name>/start')
def json_start(node_name, process_name):
    if session.get('logged_in'):
        if session['usertype'] == 0 or session['usertype'] == 1:
            try:
                node_config = _CONFIG.node(node_name)
                node = Node(node_config)
                if node.connection.supervisor.startProcess(process_name):
                    LOG.info("%s started %s node's %s process .\n" % (
                        session['username'], node_name, process_name))
                    return JsonValue(process_name, node_name, "start").success()
            except xmlrpc.client.Fault as err:

                LOG.info("%s unsucces start event %s node's %s process .\n" % (
                    session['username'], node_name, process_name))
                return JsonValue(process_name, node_name, "start").error(err.faultCode, err.faultString)
        else:

            LOG.info(
                "%s is unauthorized user request for start. Start event fail for %s node's %s process .\n" % (
                    session['username'], node_name, process_name))
            return jsonify(status="error2",
                           message="You are not authorized this action")
    else:

        LOG.info("Illegal request for start to node's %s process %s .\n" % (node_name, process_name))
        return redirect(url_for('login'))


# Process stop
@app.route('/node/<node_name>/process/<process_name>/stop')
def json_stop(node_name, process_name):
    if session.get('logged_in'):
        if session['usertype'] == 0 or session['usertype'] == 1:
            try:
                node_config = _CONFIG.node(node_name)
                node = Node(node_config)
                if node.connection.supervisor.stopProcess(process_name):
                    LOG.info("%s stopped %s node's %s process .\n" % (
                        session['username'], node_name, process_name))
                    return JsonValue(process_name, node_name, "stop").success()
            except xmlrpc.client.Fault as err:
                LOG.info("%s unsucces stop event %s node's %s process .\n" % (
                    session['username'], node_name, process_name))
                return JsonValue(process_name, node_name, "stop").error(err.faultCode, err.faultString)
        else:

            LOG.info(
                "%s is unauthorized user request for stop. Stop event fail for %s node's %s process .\n" % (
                    session['username'], node_name, process_name))
            return jsonify(status="error2",
                           message="You are not authorized this action")
    else:

        LOG.info("Illegal request for stop to node's %s process %s .\n" % (node_name, process_name))
        return redirect(url_for('login'))


# Node name list in the configuration file
@app.route('/node/name/list')
def getlist():
    if session.get('logged_in'):
        node_name_list = _CONFIG.node_list
        return jsonify(node_name_list=node_name_list)
    else:
        return redirect(url_for('login'))


# Show log for process
@app.route('/node/<node_name>/process/<process_name>/readlog')
def readlog(node_name, process_name):
    if session.get('logged_in'):
        if session['usertype'] == 0 or session['usertype'] == 1 or session['usertype'] == 2:
            node_config = _CONFIG.node(node_name)
            node = Node(node_config)
            log = node.connection.supervisor.tailProcessStdoutLog(process_name, 0, 500)[0]

            LOG.info("%s read log %s node's %s process .\n" % (
                session['username'], node_name, process_name))
            return jsonify(status="success", url="node/" + node_name + "/process/" + process_name + "/read", log=log)

        else:
            LOG.info(
                "%s is unauthorized user request for read log. Read log event fail for %s node's %s process .\n"
                % (session['username'], node_name, process_name))
            return jsonify(status="error", message="You are not authorized for this action")
    else:

        LOG.info("Illegal request for read log to node's %s process %s .\n" % (node_name, process_name))
        return jsonify(status="error", message="First login please")


# Add user method for only admin type user
@app.route('/add/user')
def add_user():
    if session.get('logged_in'):
        if session['usertype'] == 0:
            return jsonify(status='success')
        else:

            LOG.info(
                "Unauthorized user request for add user event. Add user event fail .\n")
            return jsonify(status='error')


# Delete user method for only admin type user
@app.route('/delete/user')
def del_user():
    if session.get('logged_in'):
        if session['usertype'] == 0:
            cur = get_db().cursor()
            cur.execute("SELECT username, type FROM userinfo")
            users = cur.fetchall()
            usernamelist = [str(element[0]) for element in users]
            usertypelist = [str(element[1]) for element in users]
            return jsonify(status='success',
                           names=usernamelist,
                           types=usertypelist)
        else:

            LOG.info("Unauthorized user request for delete user event. Delete user event fail .\n")
            return jsonify(status='error')


@app.route('/delete/user/<username>')
def del_user_handler(username):
    if session.get('logged_in'):
        if session['usertype'] == 0:
            if username != "admin":
                cur = get_db().cursor()
                cur.execute("DELETE FROM userinfo WHERE username=?", [username])
                get_db().commit()

                LOG.info("%s user deleted .\n", username)
                return jsonify(status="success")
            else:

                LOG.info("%s  user request for delete admin user. Delete admin user event fail .\n" % (
                    session['username']))
                return jsonify(status="error",
                               message="Admin can't delete")
        else:

            LOG.info("%s is unauthorized user for request to delete a user. Delete event fail .\n" % (
                session['username']))
            return jsonify(status="error",
                           message="Only Admin can delete a user")
    else:

        LOG.info("Illegal request for delete user event.\n")
        return redirect(url_for('login'))


# Writes new user information to database
@app.route('/add/user/handler', methods=['GET', 'POST'])
def adduserhandler():
    if session.get('logged_in'):
        if session['usertype'] == 0:
            username = request.form['username']
            password = request.form['password']
            confirmpassword = request.form['confirmpassword']

            if username == "" or password == "" or confirmpassword == "":
                return jsonify(status="null",
                               message="Please enter value")
            else:
                if request.form['usertype'] == "Admin":
                    usertype = 0
                elif request.form['usertype'] == "Standart User":
                    usertype = 1
                elif request.form['usertype'] == "Only Log":
                    usertype = 2
                elif request.form['usertype'] == "Read Only":
                    usertype = 3

                cur = get_db().cursor()
                cur.execute("SELECT * FROM userinfo WHERE username=?", (username,))
                if not cur.fetchall():
                    if password == confirmpassword:
                        cur.execute("INSERT INTO userinfo VALUES(?, ?, ?)", (username, password, usertype,))
                        get_db().commit()

                        LOG.info("New user added.\n")
                        return jsonify(status="success",
                                       message="User added")
                    else:

                        LOG.info("Passwords didn't match at add user event.\n")
                        return jsonify(status="warning",
                                       message="Passwords didn't match")
                else:

                    LOG.info("Username is avaible at add user event.\n")
                    return jsonify(status="warning",
                                   message="Username is avaible. Please select different username")
        else:

            LOG.info("%s is unauthorized user for request to add user event. Add user event fail .\n" % (
                session['username']))
            return jsonify(status="error",
                           message="Only Admin can add a user")
    else:

        LOG.info("Illegal request for add user event.\n")
        return jsonify(status="error",
                       message="First login please")


@app.route('/change/password/<username>')
def changepassword(username):
    if session.get('logged_in'):
        if session['username'] == username:
            return jsonify(status="success")
        else:

            LOG.info("%s user request to change %s 's password. Change password event fail\n" % (
                session['username'], username))
            return jsonify(status="error",
                           message="You can only change own password.")
    else:

        LOG.info("Illegal request for change %s 's password event.\n", username)
        return redirect(url_for('login'))


@app.route('/change/password/<username>/handler', methods=['POST'])
def change_password_handler(username):
    if session.get('logged_in'):
        if session['username'] == username:
            cur = get_db().cursor()
            cur.execute("SELECT password FROM userinfo WHERE username=?", (username,))
            ar = [str(r[0]) for r in cur.fetchall()]
            if request.form['old'] == ar[0]:
                if request.form['new'] == request.form['confirm']:
                    if request.form['new'] != "":
                        cur.execute("UPDATE userinfo SET password=? WHERE username=?", [request.form['new'], username])
                        get_db().commit()
                        LOG.info("%s user change own password.\n" % (session['username']))

                        return jsonify(status="success")
                    else:
                        return jsonify(status="null",
                                       message="Please enter valid value")
                else:

                    LOG.info(
                        "Passwords didn't match for %s 's change password event. Change password event fail .\n"
                        % (session['username']))
                    return jsonify(status="error", message="Passwords didn't match")
            else:

                LOG.info(
                    "Old password is wrong for %s 's change password event. Change password event fail .\n"
                    % session['username'])
                return jsonify(status="error", message="Old password is wrong")
        else:

            LOG.info("%s user request to change %s 's password. Change password event fail\n" % (
                session['username'], username))
            return jsonify(status="error", message="You can only change own password.")
    else:

        LOG.info("Illegal request for change %s 's password event.\n", username)
        return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(error):
    return render_template('page_not_found.html'), 404


if __name__ == '__main__':
    from logging.handlers import RotatingFileHandler

    formatter = logging.Formatter()
    if ACTIVITY_LOG:
        handle = RotatingFileHandler(ACTIVITY_LOG, maxBytes=1024 * 1024, backupCount=9)
        handle.setFormatter(formatter)
        handle.setLevel('INFO')
        logging.basicConfig(handlers=[handle])
    else:
        logging.basicConfig(format=_LOG_FMT, level='DEBUG')
    app.run(debug=True, host=HOST, port=9002)


