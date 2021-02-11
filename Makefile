SOURCE=	src
EDUIDUSERDB= ../eduid-userdb/src
EDUIDAM= ../eduid-am/eduid_am
EDUIDMSG= ../eduid_msg/eduid_msg

test:
	pytest

reformat:
	isort --line-width 120 --atomic --project eduid_common --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)

typecheck:
	mypy --ignore-missing-imports $(SOURCE)

typecheck_extra:
	mypy --ignore-missing-imports $(EDUIDUSERDB) $(EDUIDAM) $(EDUIDMSG) $(SOURCE)
