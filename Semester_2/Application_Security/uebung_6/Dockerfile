FROM python:3.9-alpine

RUN pip install pylint 

WORKDIR /code

ENTRYPOINT ["pylint"]
CMD ["--help"]