"""What the stand-ins for Bitwarden's SDK read: each secret's identifier,
from BWS_EXISTING, the secrets a scenario says the project holds, and the
values of those asked for by id. Each read is logged, so a scenario can say
which values reached pubsec: sdk-reads.log, beside the stand-ins' own log. A stand-in for bws refuses `secret list`, which
gives every value of a project: pubsec looks names up with the SDK instead."""

PROJECT_ID = "11111111-2222-3333-4444-555555555555"
ORGANIZATION_ID = "99999999-2222-3333-4444-555555555555"

# Appended to each stand-in SDK, which defines Answer(success, error_message=None).
READS = f'''

class _Data:
    def __init__(self, data):
        self.data = data


class _Identifier:
    def __init__(self, held):
        self.id, self.key = held["id"], held["key"]
        self.organization_id = held.get("organizationId", "{ORGANIZATION_ID}")
        self.project_ids = [held.get("projectId", "{PROJECT_ID}")]


class _Held(_Identifier):
    def __init__(self, held):
        super().__init__(held)
        self.value = held.get("value", "")


def _read(record):
    beside = os.path.dirname(os.environ.get("FAKE_LOG") or os.environ["BWS_LOG"])
    with open(os.path.join(beside, "sdk-reads.log"), "a") as out:
        out.write(json.dumps(record) + "\\n")


def _existing():
    return json.loads(os.environ.get("BWS_EXISTING", "[]"))


def listed(organization):
    _read({{"call": "list", "organization": str(organization)}})
    answer = Answer(True)
    answer.data = _Data([_Identifier(held) for held in _existing()])
    return answer


def got(ids):
    _read({{"call": "get", "ids": [str(i) for i in ids]}})
    by_id = {{held["id"]: held for held in _existing()}}
    answer = Answer(True)
    answer.data = _Data([_Held(by_id[str(i)]) for i in ids if str(i) in by_id])
    return answer
'''

# Each stand-in SDK's Secrets class takes these two methods.
METHODS = '''
    def list(self, organization):
        return listed(organization)

    def get_by_ids(self, ids):
        return got(ids)
'''

# In place of a stand-in bws's `secret list` branch.
REFUSED_LIST = '''elif args[:2] == ["secret", "list"]:
    sys.stderr.write("the stand-in bws refuses secret list: it would give every value of the project\\n")
    sys.exit(3)
'''
