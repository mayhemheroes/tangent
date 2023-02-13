# Build Stage
FROM fuzzers/atheris:2.0.7-python3.9

ADD . /src
WORKDIR /src
RUN python3 -m pip install .
RUN python3 -m pip uninstall -y gast && python3 -m pip install gast==0.2.2  # gast compatability problem (requires gast.Num)

CMD ["/src/mayhem/fuzz_deriv.py"]
