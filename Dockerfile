ARG conjure_tag=2.3.0
FROM conjurecp/conjure-runtime:$conjure_tag

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y \
      socat \
#    && apt-get upgrade -y \
#      bash \
    && rm -rf /var/lib/apt/lists/*


COPY bashttpd.sh index.html ./

CMD ["bash","bashttpd.sh", "-s"]
