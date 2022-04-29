ARG conjure_tag=2.3.0
FROM conjurecp/conjure-runtime:$conjure_tag

COPY bashttpd.sh index.html ./

CMD ["bash","bashttpd.sh", "-s"]
