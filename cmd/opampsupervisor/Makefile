# Preserve the imported upstream struct layout until package changes are
# made as separate, reviewable patches.
SKIP_FIELDALIGNMENT := true

include ../../Makefile.Common

e2e-test:
	make -C ../../ otelcontribcol
	go test -v $(GOTEST_RACE_OPT) --tags=e2e .
