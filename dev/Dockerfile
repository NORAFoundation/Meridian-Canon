FROM postgres:16-bookworm

# PostGIS 3.4 + pgvector + pg_trgm (included in postgres-contrib)
RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends \
       postgresql-16-postgis-3 \
       postgresql-16-pgvector \
  && rm -rf /var/lib/apt/lists/*

# pg_trgm and btree_gin are bundled with postgresql-16 (no extra install needed)

# Custom postgresql.conf tweaks for development
RUN echo "shared_preload_libraries = 'pg_stat_statements'" >> /usr/share/postgresql/postgresql.conf.sample

EXPOSE 5432
