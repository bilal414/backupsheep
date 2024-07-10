FROM backupsheep-base

RUN mkdir /code
WORKDIR /code

# install dependencies
COPY requirements.txt requirements.txt
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# copy project
COPY . /code/

COPY _nginx/default_80.conf /etc/nginx/sites-available/default

EXPOSE 80

COPY init.sh /usr/local/bin/
RUN chmod u+x /usr/local/bin/init.sh

#COPY init.sh init.sh

ENTRYPOINT ["/usr/local/bin/init.sh"]
