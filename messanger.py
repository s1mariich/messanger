import datetime
import string
import tkinter as tk
import hashlib
import uuid
from tkinter import scrolledtext, font
from tkinter.messagebox import showinfo

users = "users.txt"
forum1 = "forum1.txt"
forum2 = "forum2.txt"
forum3 = "forum3.txt"

HEIGHT = 800
WIDTH = 600


class MessengerApp:
    PACKED_FRAME = []

    def __init__(self, master, user):
        self.user = user
        self.master = master
        self.master.title("Messanger")
        self.master.geometry("800x600+300+150")
        self.master.resizable(False, False)

        self.commentImg = tk.PhotoImage(file="./comment.png")
        self.likeImg = tk.PhotoImage(file="./like.png")
        self.unlikeImg = tk.PhotoImage(file="./unlike.png")

        self.side_frame = tk.Frame(self.master, bg="#b4c7f7")
        self.side_frame.pack(side="left", fill="y")

        self.mid_frame = tk.Frame(self.master)
        self.mid_frame.pack(side="right", fill="both", expand=True)

        self.data1 = self.edit("forum1.txt")
        self.data2 = self.edit("forum2.txt")
        self.data3 = self.edit("forum3.txt")

        self.canvas = tk.Canvas()
        self.chat1 = tk.Button(self.side_frame, bg="#a2b3de", text="Чат 1", width=15, relief="flat",
                               anchor="nw", font=("", 12),
                               command=lambda: self.create_chat(self.chat1, self.data1))
        self.chat1.pack()

        self.chat2 = tk.Button(self.side_frame, bg="#a2b3de", text="Чат 2", width=15, relief="flat",
                               anchor="nw", font=("", 12),
                               command=lambda: self.create_chat(self.chat2, self.data2))
        self.chat2.pack()

        self.chat3 = tk.Button(self.side_frame, bg="#a2b3de", text="Чат 3", width=15, relief="flat",
                               anchor="nw", font=("", 12),
                               command=lambda: self.create_chat(self.chat3, self.data3))
        self.chat3.pack()

        self.chat1.invoke()

    def edit(self, file):
        data = []
        try:
            open(file, "r")
        except IOError:
            open(file, "w").close()
        with open(file, "r") as f:
            f.readline()
            for line in f.readlines():
                line = line.split("/")
                line[-1] = line[-1].replace("\n", "")
                line[2] = line[2].translate(str.maketrans('', '', string.punctuation)).split()
                line[3] = int(line[3])
                data.append(line)
        return data

    def create_chat(self, btn, data):
        frame = tk.Frame(self.mid_frame)
        self.packer([frame, btn])

        chat_display = tk.Frame(frame, height=HEIGHT * 0.65)
        chat_display.pack(anchor="nw", fill="x", expand=True)

        self.canvas = tk.Canvas(chat_display, borderwidth=0, height="14c")
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        frm = tk.Frame(self.canvas)
        vsb = tk.Scrollbar(chat_display, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        frame_id = self.canvas.create_window((0, 0), window=frm)
        self.canvas.itemconfig(frame_id, width=self.canvas.winfo_reqwidth() + 250)
        self.canvas.pack(side="left", fill="both", expand=True)

        frm.bind("<Configure>", lambda event, canvas=self.canvas: canvas.configure(scrollregion=canvas.bbox("all")))

        message_entry = tk.Entry(frame, font=("", 12))
        message_entry.pack(anchor="nw", fill="x", expand=True, side=tk.LEFT, padx=(5, 0))

        send_button = tk.Button(frame, text="Отправить", command=lambda: self.send_message(frm, message_entry, data))

        #вот тут кнопочка не работает
        send_button.bind("<Return>", self.send_message(frm, message_entry, data))  # попытка сделать реакцию на кнопки ентер чтоб отправить сообщение

        send_button.pack(side=tk.RIGHT, pady=(0, 15), padx=5)

        for pub in data:
            self.viewMessages(frm, pub)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def send_message(self, frm, message_entry, data):
        message = message_entry.get()
        if message:
            newPub = Publication(self.user, message)
            data.append([newPub.user, newPub.text, newPub.likes, newPub.comments, str(newPub.timePublic)])
            self.viewMessages(frm, data[-1])
            message_entry.delete(0, tk.END)

    def packer(self, page):
        if not self.PACKED_FRAME == []:
            rem = self.PACKED_FRAME.pop()
            rem[0].destroy()
            rem[1]["bg"] = "#a2b3de"

        self.PACKED_FRAME.append(page)
        page[0].pack(fill="both", expand=True, anchor="nw")
        page[1]["bg"] = "#f0f0ed"

    def viewMessages(self, chat, pub):
        user, text, likes, comments, time = pub

        container = tk.Frame(chat, bg="#e3e8f5")

        tk.Label(container, text=time[:-7], anchor="nw", bg="#e3e8f5", font=("", 9)).pack(fill="x")
        text = [(user + ": " + text)[i:i + 70] for i in range(0, len(user + ": " + text), 70)]
        for i in range(len(text)):
            if i == len(text) - 1:
                tk.Label(container, text=text[i], anchor="nw", bg="#e3e8f5", font=("", 12)).pack(fill="x", side=tk.LEFT)
            else:
                tk.Label(container, text=text[i], anchor="nw", bg="#e3e8f5", font=("", 12)).pack(fill="x", pady=(5, 0))

        commCount = tk.Label(container, text=str(comments), anchor="nw", bg="#e3e8f5", font=("", 12))
        commCount.pack(side=tk.RIGHT)
        btnComm = tk.Button(container, text="comm", image=self.commentImg, relief="flat", bg="#e3e8f5",
                            command=lambda: self.comment(commCount, pub))
        btnComm.pack(side=tk.RIGHT)

        likeCount = tk.Label(container, text=str(len(likes)), anchor="nw", bg="#e3e8f5", font=("", 12))
        likeCount.pack(side=tk.RIGHT)
        btnLike = tk.Button(container, text="like", image=self.likeImg if self.user not in likes else self.unlikeImg,
                            relief="flat", bg="#e3e8f5",
                            command=lambda: self.like(likeCount, btnLike, pub))
        btnLike.pack(side=tk.RIGHT)

        container.pack(side="top", fill="both", pady=(0, 5))

    def comment(self, count, pub):
        rootComm = tk.Tk()
        commApp = CommentApp(rootComm, pub, self.user, count)
        rootComm.mainloop()

    def like(self, count, btn, pub):
        if self.user in pub[2]:
            pub[2].remove(self.user)
            btn["image"] = self.likeImg
        else:
            pub[2].append(self.user)
            btn["image"] = self.unlikeImg
        count["text"] = str(len(pub[2]))


class Publication:
    def __init__(self, user, text):
        self.likes = []
        self.comments = 0
        self.user = user
        self.text = text
        self.timePublic = datetime.datetime.now()


class CommentApp:
    def __init__(self, root, pub, currUser, count):
        self.user = currUser
        self.count = count
        self.pub = pub

        self.root = root
        self.root.title("Comment")
        self.root.geometry("600x500+400+250")

        user, text, likes, comments, time = pub

        self.file = (user + time).translate(str.maketrans('', '', string.punctuation)).replace(" ", "") + ".txt"
        self.data = self.edit(self.file)

        container = tk.Frame(self.root, bg="#e3e8f5")

        tk.Label(container, text=time[:-7], anchor="nw", bg="#e3e8f5", font=("", 9)).pack(fill="x")
        text = [(user + ": " + text)[i:i + 70] for i in range(0, len(user + ": " + text), 70)]
        for i in range(len(text)):
            tk.Label(container, text=text[i], anchor="nw", bg="#e3e8f5", font=("", 12)).pack(fill="x")

        container.pack(side="top", fill="both", pady=(0, 5), padx=10)

        self.chat_display = scrolledtext.ScrolledText(self.root, state='disabled', wrap=tk.WORD)
        self.chat_display.pack(padx=10, pady=10, fill="x", anchor="nw")

        self.message_entry = tk.Entry(self.root)
        self.message_entry.pack(padx=10, pady=(0, 10), anchor="nw", fill="x", expand=True, side=tk.LEFT)

        self.send_button = tk.Button(self.root, text="Отправить", command=self.send_comment)
        self.send_button.pack(pady=(0, 15), padx=5, side=tk.RIGHT)

        # и вот тут кнопочка

        for i in self.data:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, i)
            self.chat_display.config(state='disabled')

    def send_comment(self):
        message = self.message_entry.get()
        if message:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, self.user + ": " + message + "\n")
            self.message_entry.delete(0, tk.END)
            self.chat_display.yview(tk.END)
            self.chat_display.config(state='disabled')

            self.count["text"] = str(int(self.count["text"]) + 1)
            self.pub[3] += 1

            with open(self.file, "a") as f: f.write(self.user + ": " + message + "\n")

    def edit(self, file):
        data = []
        try:
            open(file, "r")
        except IOError:
            open(file, "a").close()
        with open(file, "r") as f:
            for line in f.readlines():
                data.append(line)
        return data


class RegisterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Register")
        self.root.geometry("400x250+400+200")
        self.root.configure(bg="#e3e8f5")
        self.root.resizable(False, False)

        self.title_label = tk.Label(self.root, text="Write your login code", font=("", 20), bg="#e3e8f5")
        self.title_label.pack(pady=(10, 10))

        self.container_login = tk.Frame(self.root, bg="#e3e8f5")
        self.login_label = tk.Label(self.container_login, text="Login: ", font=("", 14), bg="#e3e8f5")
        self.login_label.pack(anchor="nw", side=tk.LEFT, padx=(64, 0))
        self.login_entry = tk.Entry(self.container_login, width=20, font=("", 12))
        self.login_entry.pack(anchor="nw", pady=6, side=tk.RIGHT, padx=(0, 26))
        self.container_login.pack(side=tk.TOP)

        self.container_password = tk.Frame(self.root, bg="#e3e8f5")
        self.pass_label = tk.Label(self.container_password, text="Password: ", font=("", 14), bg="#e3e8f5")
        self.pass_label.pack(anchor="nw", side=tk.LEFT, padx=(45, 0))
        self.pass_entry = tk.Entry(self.container_password, width=20, font=("", 12), show="*")
        self.pass_entry.pack(anchor="nw", pady=6, side=tk.RIGHT, padx=(0, 45))
        self.container_password.pack(side=tk.TOP)

        self.container_password_repeat = tk.Frame(self.root, bg="#e3e8f5")
        self.pass_repeat_label = tk.Label(self.container_password_repeat, text="Repeat: ", font=("", 14), bg="#e3e8f5")
        self.pass_repeat_label.pack(anchor="nw", side=tk.LEFT, padx=(51, 0))
        self.pass_repeat_entry = tk.Entry(self.container_password_repeat, width=20, font=("", 12), show="*")
        self.pass_repeat_entry.pack(anchor="nw", pady=6, side=tk.RIGHT, padx=(0, 29))
        self.container_password_repeat.pack(side=tk.TOP)

        self.button_Register = tk.Button(root, text="Register", font=("", 14), width=20, border=0, bg="#b4c7f7",
                                         command=self.reg)
        self.button_Register.pack(pady=(5, 0), side=tk.TOP)

        self.button_Back = tk.Button(root, text="->back to login page<-", font=("", 10), width=20, border=0,
                                     bg="#e3e8f5", command=self.back)
        f = font.Font(self.button_Back, self.button_Back.cget("font"))
        f.configure(underline=True)
        self.button_Back.configure(font=f)
        self.button_Back.pack(pady=(5, 0), side=tk.TOP)

    def reg(self):
        per = self.login_entry.get()
        data = []
        with open(users, "r") as file:
            logs = list(file.readline().split())
            for line in file:
                data.append(list(line.split()))
        if per in logs:
            showinfo("Info", "User with that name already exists.\nPlease, choose another login.")
        else:
            if self.pass_entry.get() and self.pass_entry.get() == self.pass_repeat_entry.get():
                pers = uuid.uuid4()
                logs.append(per)
                data.append([per, hashlib.md5((self.pass_entry.get() + str(pers)).encode()).digest(), pers])
                if len(data) != 0:
                    n = data[-1][2]
                    for i in range(len(data) - 1, 0, -1):
                        data[i][2] = data[i - 1][2]
                    data[0][2] = n
                with open(users, "w") as file:
                    for i in logs: file.write(i + " ")
                    file.write("\n")
                    for i in data:
                        for j in i: file.write(str(j) + " ")
                        file.write("\n")
                showinfo(title="Info", message="User has registered")
            elif not self.pass_entry.get():
                showinfo(title="Info", message="Enter the password, please")
            else:
                showinfo(title="info", message="Passwords are not the same")

    def back(self):
        self.root.destroy()
        root_login = tk.Tk()
        AuthorizationApp(root_login)
        root_login.mainloop()


class AuthorizationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authorization")
        self.root.geometry("400x250+400+200")
        self.root.configure(bg="#e3e8f5")
        self.root.resizable(False, False)

        self.title_label = tk.Label(self.root, text="Welcome to our chat!", font=("", 24), bg="#e3e8f5")
        self.title_label.pack(pady=(20, 10))

        self.container_login = tk.Frame(self.root, bg="#e3e8f5")
        self.login_label = tk.Label(self.container_login, text="Login: ", font=("", 14), bg="#e3e8f5")
        self.login_label.pack(anchor="nw", side=tk.LEFT, padx=(64, 0))
        self.login_entry = tk.Entry(self.container_login, width=20, font=("", 12))
        self.login_entry.pack(anchor="nw", pady=6, side=tk.RIGHT, padx=(0, 26))
        self.container_login.pack(side=tk.TOP)

        self.container_password = tk.Frame(self.root, bg="#e3e8f5")
        self.pass_label = tk.Label(self.container_password, text="Password: ", font=("", 14), bg="#e3e8f5")
        self.pass_label.pack(anchor="nw", side=tk.LEFT, padx=(45, 0))
        self.pass_entry = tk.Entry(self.container_password, width=20, font=("", 12), show="*")
        self.pass_entry.pack(anchor="nw", pady=6, side=tk.RIGHT, padx=(0, 45))
        self.container_password.pack(side=tk.TOP)

        self.button_Login = tk.Button(root, text="Login", font=("", 14), width=20, border=0, bg="#b4c7f7",
                                      command=self.check)
        self.button_Login.pack(pady=(10, 0), side=tk.TOP)

        self.button_Register = tk.Button(root, text="Register", font=("", 14), width=20, border=0, bg="#b4c7f7",
                                         command=self.register)
        self.button_Register.pack(pady=(5, 0), side=tk.TOP)

    def check(self):
        per = self.login_entry.get()
        data = []
        with open(users, "r") as file:
            logs = list(file.readline().split())
            for line in file:
                data.append(list(line.split()))
        if per not in logs:
            showinfo(title="Info", message="There is no user with that name")
        else:
            ind = logs.index(per)
            if data[ind][1] == str(hashlib.md5((self.pass_entry.get() + data[-ind - 1][2]).encode()).digest()):
                self.root.destroy()
                root = tk.Tk()
                app = MessengerApp(root, per)
                root.mainloop()
                self.write(app)
            else:
                showinfo(title="Info", message="Password is wrong")

    def register(self):
        self.root.destroy()
        root_reg = tk.Tk()
        RegisterApp(root_reg)
        root_reg.mainloop()

    def write(self, app):
        datas = [app.data1, app.data2, app.data3]
        for i in range(1, 4):
            with open("forum" + str(i) + ".txt", "w") as file:
                for j in datas[i - 1]:
                    file.write("\n" + j[0] + "/" + j[1] + "/" + str(j[2]) + "/" + str(j[3]) + "/" + str(j[4]))




rootAuth = tk.Tk()
appAuth = AuthorizationApp(rootAuth)
rootAuth.mainloop()
