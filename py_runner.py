import time
import aiosqlite
import aiofiles
import subprocess
import os
import sqlite3
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters, CallbackQueryHandler, Defaults
from telegram.constants import ParseMode
from telegram import Update, ReplyKeyboardMarkup, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters, CallbackQueryHandler
import telegram.error
from dotenv import load_dotenv
import asyncio
load_dotenv()
telegram_bot_token = os.getenv("bot_token")
administrator_id = int(os.getenv("admin_id"))
database_connection = None
forbidden_commands_list = ["os.remove", "base64", "marshal", "pickle", "os.rmdir", "os.rename", "os.system", "os.chdir", "os.environ", "shutil.", "subprocess.", "popen", "call", "check_output", "getstatusoutput", "eval(", "exec(", "getattr", "setattr", "__builtins__", "__subclasses__", "__globals__", "socket.", "requests.", "urllib.", "http.client", "smtplib", "telnetlib", "multiprocessing", "threading", "fork", "itertools.cycle", "sys.modules", "sys.argv", "pathlib.", "eval"]
user_contact_state = {}
async def scan_file_security(target_file_path):
    if not os.path.exists(target_file_path):
        return False
    async with aiofiles.open(target_file_path, "r", encoding='utf-8') as security_file:
        original_content = await security_file.read()
    check_content = original_content.replace(" ", "").replace("\n", "").replace("\r", "").lower()
    for forbidden_word in forbidden_commands_list:
        if forbidden_word.replace(" ", "").lower() in check_content:
            await log_event(administrator_id, f"security alert: forbidden command '{forbidden_word}' detected in {target_file_path}")
            return True
    return False
async def send_daily_logs(context: ContextTypes.DEFAULT_TYPE):
    global database_connection
    log_file_path = "master_log.txt"
    database_file_path = "bot_database.db"
    current_execution_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if os.path.exists(log_file_path):
        try:
            await context.bot.send_document(chat_id=administrator_id, document=log_file_path, caption=f"text log sent at: {current_execution_time}")
        except Exception as e:
            await handle_system_error(None, context, e, "daily_logs_text")
    if os.path.exists(database_file_path):
        try:
            await context.bot.send_document(chat_id=administrator_id, document=database_file_path, caption=f"sqlite database sent at: {current_execution_time}")
        except Exception as e:
            await handle_system_error(None, context, e, "daily_logs_text")
async def log_event(user_id, action_description, user_metadata=None, file_path=None):
    global database_connection
    current_time_string = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_fingerprint = "no-data"
    if user_metadata:
        user_fingerprint = f"firstname: {user_metadata.first_name}|username: {user_metadata.username}|userid: {user_metadata.id}"
    file_size_information = ""
    if file_path and os.path.exists(file_path):
        size_in_bytes = os.path.getsize(file_path)
        file_size_information = f" | file size: {size_in_bytes} bytes"
    log_entry_message = f"[{current_time_string}] fingerprint: {user_fingerprint} | user {user_id}: {action_description}{file_size_information}\n"
    async with aiofiles.open("master_log.txt", "a", encoding="utf-8") as master_log_file:
        await master_log_file.write(log_entry_message)
    async with aiofiles.open(f"log_{user_id}.txt", "a", encoding="utf-8") as individual_user_log_file:
        await individual_user_log_file.write(log_entry_message)
    if database_connection:
        await database_connection.execute(
            "INSERT INTO user_logs (user_id, fingerprint, action, timestamp) VALUES (?, ?, ?, ?)",
            (str(user_id), user_fingerprint, action_description, current_time_string)
        )
        await database_connection.commit()
async def check_banned_users(user_id):
    if not os.path.exists("banned_users.txt"):
        return False
    async with aiofiles.open("banned_users.txt", "r", encoding="utf-8") as banned_file:
        content = await banned_file.read()
        banned_list = content.splitlines()
    return str(user_id) in banned_list
async def handle_system_error(update: Update, context: ContextTypes.DEFAULT_TYPE, error_exception, function_name):
    current_user_id = "unknown"
    if update and update.effective_user:
        current_user_id = str(update.effective_user.id)
    error_details_text = f"system error in {function_name}: {str(error_exception)}"
    await log_event(administrator_id, f"bot alert: {error_details_text}")
    try:
        await context.bot.send_message(chat_id=administrator_id, text=f"message from error handler: {error_details_text}")
    except:
        pass
    if update and update.effective_message:
        try:
            information_user_error = "an internal error occurred. report sent to administrator."
            await update.effective_message.reply_text(information_user_error)
            await log_event(current_user_id, f"bot sent to user: {information_user_error}")
        except:
            pass
async def execute_python_code(user_identifier, update: Update, context: ContextTypes.DEFAULT_TYPE, user_metadata=None):
    user_id_internal = str(user_identifier)
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    await log_event(user_id_internal, "bot action: started typing (processing request)", user_metadata)
    if await check_banned_users(user_id_internal):
        await log_event(user_id_internal, "access denied: banned user", user_metadata)
        await update.effective_message.reply_text("you are banned from bot by admin")
        return
    target_file_path = f"{user_id_internal}.py"
    is_execution_safe = await scan_file_security(target_file_path)
    if is_execution_safe:
        if os.path.exists(target_file_path):
            await context.bot.send_document(chat_id=administrator_id, document=target_file_path, caption=f"Malicious code from user {user_id_internal}")
            os.remove(target_file_path)
        await log_event(user_id_internal, "execution blocked: malicious content in file", user_metadata)
        await update.effective_message.reply_text("security violation: code contains forbidden commands")
        return
    if not os.path.exists(target_file_path):
        await update.effective_message.reply_text("first send your code.")
        return
    files_before = set(os.listdir("."))
    await log_event(user_id_internal, "execution started", user_metadata)
    start_execution_time = time.perf_counter()
    process = await asyncio.create_subprocess_exec(
        "python", target_file_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
        end_execution_time = time.perf_counter()
        execution_duration = end_execution_time - start_execution_time
        final_seconds = round(execution_duration, 3)
        out_text = stdout.decode('utf-8', errors='replace').strip()
        err_text = stderr.decode('utf-8', errors='replace').strip()
        exit_code = process.returncode
        if out_text:
            await update.effective_message.reply_text(out_text)
            await log_event(user_id_internal, f"bot sent: output: {out_text}", user_metadata)
        if err_text:
            await update.effective_message.reply_text(err_text)
            await log_event(user_id_internal, f"bot sent error: {err_text}", user_metadata)
        status_message = f"process finished with exit code {exit_code}"
        await update.effective_message.reply_text(status_message)
        await log_event(user_id_internal, f"bot sent execution finished with code {exit_code}", user_metadata)
        await update.effective_message.reply_text(f"code execution time: {final_seconds} seconds")
        await log_event(user_id_internal, f"bot sent: execution finished in {final_seconds}s", user_metadata)
        files_after = set(os.listdir("."))
        new_files = files_after - files_before
        for f_name in new_files:
            if f_name != target_file_path and os.path.isfile(f_name):
                try:
                    await context.bot.send_document(chat_id=update.effective_chat.id, document=f_name, caption=f"file generated: {f_name}")
                    await log_event(user_id_internal, f"file sent: {f_name}", user_metadata, f_name)
                    os.remove(f_name)
                except Exception as fe:
                    await log_event(user_id_internal, f"error sending file {f_name}: {str(fe)}", user_metadata)
    except asyncio.TimeoutError:
        try:
            process.kill()
        except Exception as e:
            await handle_system_error(update, context, e, "execute_python_code_file_delivery")
        await update.effective_message.reply_text("execution timed out.")
        await log_event(user_id_internal, "timeout error", user_metadata)
    finally:
        if os.path.exists(target_file_path):
            os.remove(target_file_path)
my_defaults = Defaults(parse_mode=None)
bot_application = ApplicationBuilder().token(telegram_bot_token).defaults(my_defaults).connect_timeout(300).read_timeout(300).write_timeout(300).build()
async def start_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.message.from_user.id)
    user_metadata = update.message.from_user
    if await check_banned_users(user_id):
        ban_reply_message = "you are banned from bot by admin"
        await log_event(user_id, "access denied: banned user", user_metadata)
        await update.message.reply_text(ban_reply_message)
        return
    registered_users = []
    if os.path.exists("users_list.txt"):
        async with aiofiles.open("users_list.txt", "r") as user_file:
            content = await user_file.read()
            registered_users = content.splitlines()
    if user_id not in registered_users:
        async with aiofiles.open("users_list.txt", "a") as user_file:
            await user_file.write(user_id + "\n")
    welcome_message_text = "welcome to this bot"
    await log_event(user_id, "user started the bot", user_metadata)
    await update.message.reply_text(welcome_message_text, reply_markup=ReplyKeyboardMarkup([["/start", "/help"], ["/contact"]], resize_keyboard=True))
bot_application.add_handler(CommandHandler("start", start_command_handler))
async def send_all_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != administrator_id:
        return
    broadcast_message_text = " ".join(context.args)
    if not broadcast_message_text:
        error_message_text = "please write a message after /sendall"
        await update.message.reply_text(error_message_text)
        await log_event(administrator_id, f"bot sent: {error_message_text}", update.message.from_user)
        return
    await log_event(administrator_id, f"admin broadcast: {broadcast_message_text}", update.message.from_user)
    try:
        async with aiofiles.open("users_list.txt", "r") as users_list_read:
            content = await users_list_read.read()
            registered_users_to_send = content.splitlines()
    except FileNotFoundError:
        await update.message.reply_text("error: users_list.txt not found.")
        await log_event(administrator_id, f"bot sent: error: users_list.txt not found", update.message.from_user)
        return
    sent_count = 0
    for target_user_id_item in registered_users_to_send:
        user_id = target_user_id_item.strip()
        if not user_id:
            continue
        try:
            admin_broadcast_content = f"broadcast from admin: {broadcast_message_text}"
            await context.bot.send_message(chat_id=target_user_id_item, text=admin_broadcast_content)
            sent_count += 1
        except telegram.error.TelegramError as e:
            await log_event(administrator_id, f"Broadcast failed for {user_id}: {str(e)}")
            continue
    success_confirmation_text = f"done! message sent to {sent_count} users."
    await update.message.reply_text(success_confirmation_text)
    await log_event(administrator_id, f"bot sent: {success_confirmation_text}")
bot_application.add_handler(CommandHandler("sendall", send_all_command_handler))
help_guide_message_text= """
User Guide: How to use this Bot
Introduction:
This bot is a powerful Python code runner designed to help you test and execute scripts directly within Telegram in a safe environment.
What this bot does for beginners:
If you are new to programming, this bot acts like a portable coding notebook. You can write Python commands and see the results immediately without installing any software on your phone or computer.
For Professional Users:
You can execute complex scripts and handle files. If your code generates any files (like .txt, .csv, or images), the bot will automatically detect and send them back to you.
Library Requests:
If your code requires a library that is not installed, please send the library name to the admin using the /contact command. If approved, the admin will install it and notify you.
Input Limitation:
Please note that due to Telegram\'s limitations, this bot does not support interactive input like the input() function. Your code should run to completion automatically.
Security Warning:
The bot features an automated security scanner. Attempting to use forbidden commands or malicious scripts will trigger an automatic security alert to the admin and may lead to a permanent ban from the bot.
How to Run Code:
1. Simply type your Python code or paste it into the chat.
2. The bot will save your code and provide a Run button.
3. Click the button to execute and receive the output.
4. You can also upload .py files directly to run them.
A Sincere Apology:
Telegram formatting rules often interfere with code characters. Since double underscores (__) are used for bold text, they might be hidden or cause script errors. To prevent this, especially when writing Classes or using special variables, code must be wrapped between two sets of triple backticks (```). This applies to messages and file captions alike; place these symbols at the very beginning and the very end.
Code Analysis Feature:
The bot now sends the exact execution time in a separate message. This allows for detailed performance analysis and code speed optimization.
How to Format Your Code (Class Example):
If you are writing a Class like this, wrap it in triple backticks as shown here:
```
class ColorBox:
    def __init__(self, box_color):
        self.color = box_color
        self.books = ["RedBook", "BlueBook"]
    def show_items(self):
        print(f"box_color: {self.color}")
        print(f"total_books: {len(self.books)}")
my_box = ColorBox("Green")
my_box.show_items()
```
Step-by-Step Explanation for Beginners:
Line 1: 'class ColorBox' creates a structure to hold data and functions.
Line 2: '__init__' is a special function that runs when the box is created.
Line 3: 'self.color' stores the specific color you give to the box.
Line 4: 'self.books' creates a list of book names inside the box.
Line 5: 'def show_items' is a function to print the information later.
Line 6: This line prints the color stored in the box.
Line 7: This line counts and prints how many books are in the list.
Line 8: 'my_box' creates an actual Green box using our structure.
Line 9: This line tells the box to show its color and book count.
"""
async def help_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id_help = str(update.message.from_user.id)
    user_metadata_help = update.message.from_user
    if await check_banned_users(user_id_help):
        ban_reply_help = "you are banned from bot by admin"
        await log_event(user_id_help, "access denied: banned user tried to interact with bot", user_metadata_help)
        await update.message.reply_text(ban_reply_help)
        await log_event(user_id_help, f"bot sent: {ban_reply_help}", user_metadata_help)
        return
    await log_event(user_id_help, "user viewed help guide", user_metadata_help)
    await update.message.reply_text(help_guide_message_text)
    await log_event(user_id_help, f"bot sent: {help_guide_message_text}", user_metadata_help)
bot_application.add_handler(CommandHandler("help", help_command_handler))
async def handle_user_messages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id_message = str(update.message.from_user.id)
    user_metadata_message = update.message.from_user
    if await check_banned_users(user_id_message):
        ban_reply_message = "you are banned from bot by admin"
        await log_event(user_id_message, "access denied: banned user tried to interact with bot", user_metadata_message)
        await update.message.reply_text(ban_reply_message)
        await log_event(user_id_message, f"bot sent: {ban_reply_message}", user_metadata_message)
        return
    if user_contact_state.get(user_id_message):
        user_contact_message_text = update.message.text
        await log_event(user_id_message, f"user sent message to admin: {user_contact_message_text}", user_metadata_message)
        message_to_admin_content = f"new message from {user_id_message}:\n{user_contact_message_text}"
        await context.bot.send_message(chat_id=administrator_id, text=message_to_admin_content)
        contact_success_text = "your message sent to admin."
        await update.message.reply_text(contact_success_text)
        await log_event(user_id_message, f"bot sent: {contact_success_text}", user_metadata_message)
        user_contact_state[user_id_message] = False
        return
    user_message_content_text = update.message.text
    if update.message.entities:
        for entity in update.message.entities:
            if entity.type in ['code', 'pre']:
                user_message_content_text = update.message.text[entity.offset : entity.offset + entity.length]
                break
    security_check_content_text = user_message_content_text.replace(" ", "").lower().strip()
    for forbidden_word_item in forbidden_commands_list:
        if forbidden_word_item in security_check_content_text:
            security_denial_message_text = "i cannot execute this code due to security reasons"
            await update.message.reply_text(security_denial_message_text)
            await log_event(user_id_message, f"bot sent: {security_denial_message_text}", user_metadata_message)
            await log_event(user_id_message, f"security alert: user entered restricted code: {user_message_content_text}", user_metadata_message)
            alert_to_admin_text = f" security alert: user {user_id_message}, entered bad code! {user_message_content_text}"
            await context.bot.send_message(chat_id=administrator_id, text=alert_to_admin_text)
            return
    python_file_name_save = f"{user_id_message}.py"
    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action="typing")
    await log_event(user_id_message, "bot action: typing status shown to user", user_metadata_message)
    async with aiofiles.open(python_file_name_save, "w", encoding="utf-8") as python_file:
        await python_file.write(user_message_content_text)
    await log_event(user_id_message, f"user sent code content: {user_message_content_text}", user_metadata_message)
    await log_event(user_id_message, "saved user code to file", user_metadata_message, python_file_name_save)
    run_button_inline = [[InlineKeyboardButton("run", callback_data="run_code")]]
    run_inline_keyboard_markup = InlineKeyboardMarkup(run_button_inline)
    save_success_message_text = "your code saved succesfully, here is your file: clik run to run your code"
    await update.message.reply_text(save_success_message_text, reply_markup=run_inline_keyboard_markup)
    await log_event(user_id_message, f"bot sent: {save_success_message_text}", user_metadata_message)
    await context.bot.send_document(chat_id=update.effective_chat.id, document=python_file_name_save)
    await log_event(user_id_message, f"bot sent python file to user: {python_file_name_save}", user_metadata_message, python_file_name_save)
bot_application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_user_messages))
async def run_code_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id_run = str(update.message.from_user.id)
    user_metadata_run = update.message.from_user
    if await check_banned_users(user_id_run):
        ban_reply_run = "you are banned from bot by admin"
        await log_event(user_id_run, "access denied: banned user tried to interact with bot", user_metadata_run)
        await update.message.reply_text(ban_reply_run)
        await log_event(user_id_run, f"bot sent: {ban_reply_run}", user_metadata_run)
        return
    await execute_python_code(user_id_run, update.message, user_metadata_run)
bot_application.add_handler(CommandHandler("run", run_code_command_handler))
async def ban_user_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != administrator_id:
        return
    if not context.args:
        await log_event(administrator_id, "admin error: sent /ban without user id", update.message.from_user)
        error_ban_text = "please send an id to ban"
        await update.message.reply_text(error_ban_text)
        await log_event(administrator_id, f"bot sent: {error_ban_text}", update.message.from_user)
        return
    target_user_id_ban = context.args[0]
    if len(context.args) > 1:
        reason_for_ban_text = " ".join(context.args[1:])
    else:
        reason_for_ban_text = ""
    async with aiofiles.open("banned_users.txt", "a", encoding="utf-8") as banned_users_file_append:
        await banned_users_file_append.write(target_user_id_ban + "\n")
    if reason_for_ban_text:
        ban_notify_message = f"you are banned from bot by admin. reason: {reason_for_ban_text}"
        admin_log_entry = f"admin banned user: {target_user_id_ban} | reason: {reason_for_ban_text}"
    else:
        ban_notify_message = "you are banned from bot by admin"
        admin_log_entry = f"admin banned user: {target_user_id_ban} | (no reason provided)"
    try:
        await context.bot.send_message(chat_id=target_user_id_ban, text=ban_notify_message)
        await log_event(target_user_id_ban, f"bot sent: {ban_notify_message}", update.message.from_user)
    except telegram.error.TelegramError:
        await log_event(target_user_id_ban, "could not send ban message (user blocked bot)", update.message.from_user)
    success_ban_text = f"{target_user_id_ban} user banned successfully"
    await update.message.reply_text(success_ban_text)
    await log_event(administrator_id, admin_log_entry, update.message.from_user)
bot_application.add_handler(CommandHandler("ban", ban_user_handler))
async def unban_user_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != administrator_id:
        return
    unbanned_user_id_target = " ".join(context.args)
    if not unbanned_user_id_target:
        await log_event(administrator_id, "admin error: sent /unban without user id", update.message.from_user)
        error_unban_text = "please send an id to unban"
        await update.message.reply_text(error_unban_text)
        await log_event(administrator_id, f"bot sent: {error_unban_text}", update.message.from_user)
        return
    try:
        async with aiofiles.open("banned_users.txt", "r", encoding="utf-8") as file_banned:
            content = await file_banned.read()
            lines = content.splitlines()
        async with aiofiles.open("banned_users.txt", "w", encoding="utf-8") as file_banned:
            for line in lines:
                if line != unbanned_user_id_target:
                    await file_banned.write(line + "\n")
        try:
            unban_notify_message = "your account has been unbanned by admin"
            await context.bot.send_message(chat_id=unbanned_user_id_target, text=unban_notify_message)
            await log_event(unbanned_user_id_target, f"bot sent: {unban_notify_message}", update.message.from_user)
        except telegram.error.TelegramError:
            await log_event(unbanned_user_id_target, "could not send unban message (user blocked bot)", update.message.from_user)
        success_unban_text = f"{unbanned_user_id_target} user unbanned successfully"
        await update.message.reply_text(success_unban_text)
        await log_event(administrator_id, f"admin unbanned user: {unbanned_user_id_target}", update.message.from_user)
    except Exception as e:
        await update.message.reply_text(f"error in unban process: {e}")
bot_application.add_handler(CommandHandler("unban", unban_user_handler))
async def contact_admin_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id_contact = str(update.message.from_user.id)
    user_metadata_contact = update.message.from_user
    if await check_banned_users(user_id_contact):
        ban_reply_contact = "you are banned from bot by admin"
        await update.message.reply_text(ban_reply_contact)
        await log_event(user_id_contact, f"bot sent: {ban_reply_contact}", user_metadata_contact)
        return
    user_contact_state[user_id_contact] = True
    contact_prompt_text = "please send your message now to be sent to the admin."
    await update.message.reply_text(contact_prompt_text)
    await log_event(user_id_contact, "user initiated contact mode", user_metadata_contact)
bot_application.add_handler(CommandHandler("contact", contact_admin_handler))
async def reply_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != administrator_id:
        return
    if len(context.args) < 2:
        reply_error_text = "usage: /reply user_id text"
        await update.message.reply_text(reply_error_text)
        await log_event(administrator_id, f"bot sent: {reply_error_text}", update.message.from_user)
        return
    target_id_reply = context.args[0]
    admin_reply_text_content = " ".join(context.args[1:])
    try:
        full_reply_message = f"admin reply: {admin_reply_text_content}"
        await context.bot.send_message(chat_id=target_id_reply, text=full_reply_message)
        reply_success_text = f"message sent to {target_id_reply}"
        await update.message.reply_text(reply_success_text)
        await log_event(administrator_id, f"admin replied to {target_id_reply}: {admin_reply_text_content}", update.message.from_user)
        await log_event(target_id_reply, f"bot sent: {full_reply_message}", update.message.from_user)
    except telegram.error.TelegramError as error_details_reply:
        reply_fail_text = f"failed to send message: {str(error_details_reply)}"
        await update.message.reply_text(reply_fail_text)
        await log_event(administrator_id, f"bot sent: {reply_fail_text}", update.message.from_user)
bot_application.add_handler(CommandHandler("reply", reply_command_handler))
async def send_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != administrator_id:
        return
    if len(context.args) < 2:
        send_error_text = "usage: /send user_id text"
        await update.message.reply_text(send_error_text)
        await log_event(administrator_id, f"bot sent: {send_error_text}", update.message.from_user)
        return
    target_id_send = context.args[0]
    admin_send_text_content = " ".join(context.args[1:])
    try:
        full_send_message = f"message from admin: {admin_send_text_content}"
        await context.bot.send_message(chat_id=target_id_send, text=full_send_message)
        send_success_text = f"message sent to {target_id_send}"
        await update.message.reply_text(send_success_text)
        await log_event(administrator_id, f"admin sent to {target_id_send}: {admin_send_text_content}", update.message.from_user)
        await log_event(target_id_send, f"bot sent: {full_send_message}", update.message.from_user)
    except telegram.error.TelegramError as error_details_send:
        send_fail_text = f"failed to send message: {str(error_details_send)}"
        await update.message.reply_text(send_fail_text)
        await log_event(administrator_id, f"bot sent: {send_fail_text}", update.message.from_user)
bot_application.add_handler(CommandHandler("send", send_command_handler))
async def button_callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == "run_code":
        user_id = query.from_user.id
        await log_event(user_id, "user clicked run button", query.from_user)
        await execute_python_code(user_id, update, context, query.from_user)
bot_application.add_handler(CallbackQueryHandler(button_callback_handler))
async def handle_document_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id_doc = str(update.message.from_user.id)
    user_metadata_doc = update.message.from_user
    if await check_banned_users(user_id_doc):
        return
    received_document = update.message.document
    file_extension = os.path.splitext(received_document.file_name)[1]
    save_path = f"{user_id_doc}{file_extension}"
    try:
        telegram_file_object = await context.bot.get_file(received_document.file_id)
        await telegram_file_object.download_to_drive(save_path)
        await log_event(user_id_doc, f"uploaded file: {received_document.file_name}", user_metadata_doc, save_path)
        is_file_malicious = await scan_file_security(save_path)
        if is_file_malicious:
            alert_text = f"security alert! user {user_id_doc} sent a malicious file. file name: {received_document.file_name}"
            await context.bot.send_message(chat_id=administrator_id, text=alert_text)
            await context.bot.send_document(chat_id=administrator_id, document=save_path, caption=f"malicious file from user: {user_id_doc}")
            if os.path.exists(save_path):
                os.remove(save_path)
            await log_event(user_id_doc, f"security alert: malicious file detected and deleted: {received_document.file_name}", user_metadata_doc)
            denial_message = "i cannot accept this file due to security reasons."
            await update.message.reply_text(denial_message)
            await log_event(user_id_doc, f"bot sent: {denial_message}", user_metadata_doc)
            return
        success_message = f"file {received_document.file_name} received successfully."
        await update.message.reply_text(success_message)
        await log_event(user_id_doc, f"bot sent: {success_message}", user_metadata_doc)
    except Exception as e:
        await handle_system_error(update, context, e, "handle_document_upload")
bot_application.add_handler(MessageHandler(filters.Document.ALL, handle_document_upload))
async def search_user_logs_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.message.from_user.id != administrator_id:
        return
    if len(context.args) < 1:
        await update.message.reply_text("usage: /search user_id [count]")
        return
    search_target_id_input = context.args[0]
    if len(context.args) > 1 and context.args[1].isdigit():
        record_limit_count = int(context.args[1])
    else:
        record_limit_count = 5
    search_results_list = []
    if database_connection:
        async with database_connection.execute(
        "SELECT action, timestamp FROM user_logs WHERE user_id = ? ORDER BY id DESC LIMIT ?", 
        (search_target_id_input, record_limit_count)
        ) as cursor:
            search_results_list = await cursor.fetchall()
    if not search_results_list:
        no_log_message_text = f"no logs found for user: {search_target_id_input}"
        await log_event(administrator_id, f"bot sent {no_log_message_text}")
        await update.message.reply_text(no_log_message_text)
        return
    report_header_text = f"last {len(search_results_list)} activities for {search_target_id_input}:\n"
    report_body_text = "".join([f"[{time_item}] {action_item}\n" for action_item, time_item in search_results_list])
    await update.message.reply_text(report_header_text + report_body_text)
    await log_event(administrator_id, f"admin searched for {search_target_id_input} (count: {len(search_results_list)})", update.message.from_user)
bot_application.add_handler(CommandHandler("search", search_user_logs_handler))
scheduler_instance = AsyncIOScheduler()
scheduler_instance.add_job(send_daily_logs, 'cron', hour=0, minute=0, args=[bot_application])
async def on_startup(application):
    async with aiofiles.open("banned_users.txt", "a", encoding="utf-8") as banned_file_init:
        pass
    global database_connection
    database_connection = await aiosqlite.connect("bot_database.db")
    await database_connection.execute("CREATE TABLE IF NOT EXISTS user_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, fingerprint TEXT, action TEXT, timestamp TEXT)")
    await database_connection.commit()
    if not scheduler_instance.running:
        scheduler_instance.start()
    try:
        startup_message = "message from scheduler: bot is online and scheduler started successfully"
        await log_event(administrator_id, f"bot sent: {startup_message}")
        await application.bot.send_message(chat_id=administrator_id, text=startup_message)
    except Exception as e:
        error_details_text = f"critical startup error: {str(e)}"
        await log_event(administrator_id, error_details_text)
        try:
            await application.bot.send_message(chat_id=administrator_id, text=f"system error alert from startup:\n{error_details_text}")
        except:
            pass
bot_application.post_init = on_startup
async def on_shutdown(application):
    global database_connection
    if database_connection:
        await log_event(administrator_id, "database is closing now (shutdown sequence)")
        await database_connection.close()
bot_application.post_stop = on_shutdown
bot_application.run_polling()