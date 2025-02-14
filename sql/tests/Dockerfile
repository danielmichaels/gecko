FROM postgres:15

#COPY schema.sql /tmp/schema.sql
COPY schema.sql /docker-entrypoint-initdb.d/
COPY static.sql /docker-entrypoint-initdb.d/
#COPY init_database.sh /tmp/init_database.sh

#RUN chmod +x /tmp/init_database.sh
ENV POSTGRES_USER=dbuser
ENV POSTGRES_PASSWORD=dbuser
ENV POSTGRES_DB=db
#ENTRYPOINT ["/tmp/init_database.sh"]
