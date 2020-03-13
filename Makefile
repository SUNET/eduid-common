SOURCE=	src

reformat:
	isort --atomic --recursive $(SOURCE)
	black --line-length 120 --target-version py37 --skip-string-normalization $(SOURCE)
