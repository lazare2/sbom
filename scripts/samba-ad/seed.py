# 1,200 people in "Squad Big", written straight into the directory in one transaction: past AD's
# 1,000-entry page, so the connector's paging is tested. (samba-tool would take ten minutes.)
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

lp = LoadParm()
lp.load_default()
db = SamDB(url=lp.samdb_url(), session_info=system_session(), lp=lp)
base = str(db.domain_dn())
group = "CN=Squad Big,CN=Users," + base
db.transaction_start()
try:
    members = []
    for i in range(1200):
        dn = "CN=big%04d,CN=Users,%s" % (i, base)
        db.add({"dn": dn, "objectClass": "user", "sAMAccountName": "big%04d" % i,
                "mail": "big%04d@corp.example" % i, "userAccountControl": "512"})
        members.append(dn)
    for start in range(0, len(members), 200):
        msg = "dn: %s\nchangetype: modify\nadd: member\n" % group + "".join("member: %s\n" % m for m in members[start:start + 200])
        db.modify_ldif(msg)
    db.transaction_commit()
except Exception:
    db.transaction_cancel()
    raise
print("seeded 1200 members")
