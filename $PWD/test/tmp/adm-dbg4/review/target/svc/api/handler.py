import db
def get(q):
    return db.raw(q)
    print(q)
