FROM gcr.io/distroless/base
COPY /getawslog /getawslog
ENTRYPOINT ["/getawslog"]
