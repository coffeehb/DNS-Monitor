# coding:utf-8
import tornado.web
import tornado.httpserver
import tornado.ioloop
import tornado.options
import os.path
import xlwt
from libs.core import LogsHelper

loghelp = LogsHelper()

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        return self.get_secure_cookie("user")

class MainHandler(BaseHandler):

    def get(self):
        if not self.get_current_user():
            msg = ""
            if self.request.arguments.has_key("flg"):
                msg = self.get_argument('flg')

            if len(msg) == 0:
                msg = u"请先登录"
                href = '/'
            else:
                msg = u"登录失败"
                href = '/'

            self.write('''
                    <script language="javascript">
                    alert("%s");
                    window.location.href="%s";
                    </script>
                ''' % (msg, href))
            return
        # 下载日志
        if self.request.arguments.has_key("downPage"):
            downPage = self.get_argument('downPage')

            downPage = int(downPage)
            loghelp = LogsHelper()
            all_logs = loghelp.get_all_dnslogs()

            start = (downPage - 1) * 20
            end = downPage * 20

            download_logs = all_logs[start:end]
            self.set_header('Content-Type', 'application/octet-stream')
            self.set_header('Content-Disposition', 'attachment; filename=%s.xls' % ("dnslogs_page" + str(downPage)))
            wbk = xlwt.Workbook()
            sheet = wbk.add_sheet('dnslogs', cell_overwrite_ok=True)
            sheet.write(0, 0, u"编号")
            sheet.write(0, 1, u"请求域名")
            sheet.write(0, 2, u"解析IP")
            sheet.write(0, 3, u"记录时间")
            sheet.write(0, 4, u"端口情况")

            pi = 1
            for line in download_logs:

                log_id = str(line['id'])
                domain = line['domain']
                ip = line['ip']
                log_time = line['time']
                port = line['port']

                sheet.write(pi, 0, log_id)
                sheet.write(pi, 1, domain)
                sheet.write(pi, 2, ip)
                sheet.write(pi, 3, log_time)
                sheet.write(pi, 4, port)
                pi += 1

            wbk.save('temp/test.xls')
            with open('temp/test.xls','rb') as f:
                for lin in f.readlines():
                    self.write(lin)
            self.finish()
            return
        # 展示日志
        if self.request.arguments.has_key("dnspage"):
            dnspage = self.get_argument('dnspage')
        else:
            dnspage = 1

        loghelp = LogsHelper()
        all_logs = loghelp.get_all_dnslogs()

        page = int(dnspage)

        start = (page - 1) * 20
        end = page * 20
        show_logs = all_logs[start:end]

        all_pages, c = divmod(len(all_logs), 20)
        if c > 0:
            all_pages += 1

        list_page = []
        if (page-1) <= 0:
            p_page = 1
        else:
            p_page = page - 1

        first_one = '<li><a href="/main?dnspage=%s" aria-label="Previous"><span aria-hidden="true">«</span></a></li>' % (p_page)
        list_page.append(first_one)

        for p in range(all_pages):
            if p+1 == page:
                tmp = '	<li><a class="active" href="/main?dnspage=%s">%s</a></li>' % (p+1, p+1)
            else:
                tmp = '	<li><a href="/main?dnspage=%s">%s</a></li>' % (p+1, p+1)
            list_page.append(tmp)

        last_one = '<li><a href="/main?dnspage=%s" aria-label="Next"><span aria-hidden="true">»</span></a></li>' % (all_pages)
        list_page.append(last_one)

        link_pages = "".join(list_page)

        self.render(
            "views.html",
            total_dnslog=len(all_logs),
            show_logs=show_logs,
            current_page=page,
            link_pages=link_pages
        )


class LoginHandler(BaseHandler):
    def get(self):
        if self.request.arguments.has_key("login_out"):
            login_out = self.get_argument('login_out')
            if login_out:
                self.clear_all_cookies()
                self.redirect("/")
                return
        self.render(template_name="login.html")

    def post(self):
        username = self.get_argument("username")
        password = self.get_argument("password")
        if username == "admin" and password == "123456":
            self.set_secure_cookie("user", username)
            self.redirect(u"/main")
        else:
            self.redirect(u"/main?flg=fail")


class ErrorHandler(BaseHandler):
    def get(self):
        self.render('404.html')


def run_web():

    app = tornado.web.Application(
        handlers=[
            (r'/main', MainHandler),
            (r'/', LoginHandler),
            (r".*", ErrorHandler)

        ],
        template_path=os.path.join(os.path.dirname(__file__), 'templates'),
        static_path=os.path.join(os.path.dirname(__file__), 'static'),
        debug=True, cookie_secret="testme007/7AmGeJJFuYh7EQnp2XdTP1o/Vo="

    )

    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(int(loghelp.listen_port))
    tornado.ioloop.IOLoop.instance().start()