import sqlite3 as sql
import json
import logging
import traceback
import sys

DATABASE_NAME = 'issuer_database.db'

def test_api_key(client_id, client_secret):
    if not isinstance(client_id, str) or not isinstance(client_secret, str) :
        return False
    try:
        con = sql.connect(DATABASE_NAME) 
        cur = con.cursor()
        request = "select * from customers where client_secret='" + client_secret + "' and client_id='" + client_id + "'"
        cur.execute(request)
        data = cur.fetchone()
        con.close()
        return data
    except sql.Error as er:
        logging.error('Database error: %s', ' '.join(er.args))
        con.close()

def get_user_kyc(did):
    try: 
            with sql.connect(DATABASE_NAME) as con: #rajouter date kyc dans la table
                cur = con.cursor()
                cur.execute("select * from kycs where did='" +did+"'")
                return cur.fetchone() 
    except sql.Error as er:
            logging.error('SQLite error: %s', ' '.join(er.args))
    finally:
            con.close()


def insert_kyc(did,status,id_dossier):
    try:
            with sql.connect(DATABASE_NAME) as con:
                cur = con.cursor()
                cur.execute("INSERT INTO kycs (did,status,id) VALUES (?,?,?)",(did,status,id_dossier))
                con.commit()
                logging.info("kyc successfully added")
    except sql.Error as er: 
            print('SQLite error: %s' % (' '.join(er.args)))
            print("Exception class is: ", er.__class__)
            print('SQLite traceback: ')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))

    finally:
            con.close()


def update_kyc(did,status,id_dossier):
    try:
            with sql.connect(DATABASE_NAME) as con:
                cur = con.cursor()
                print("update kycs set status='"+status+"',id="+str(id_dossier)+" where did='"+did+"'")
                cur.execute("update kycs set status='"+status+"',id="+str(id_dossier)+" where did='"+did+"'")
                con.commit()
                msg = "kyc successfully updated"
                logging.info("msg db %s", str(msg))
    except:
            con.rollback()
            msg = "error in update operation"
            logging.info("msg db %s", str(msg))
            
    finally:
            con.close()
            logging.info("msg db %s", str(msg))