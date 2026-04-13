.PHONY: paper arxiv clean test figures

PAPER_DIR  := paper
ARXIV_DIR  := arxiv_submission
ARXIV_ZIP  := arxiv_submission.zip

# --- Paper ---

paper:
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode paper.tex || true
	cd $(PAPER_DIR) && bibtex paper || true
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode paper.tex || true
	cd $(PAPER_DIR) && pdflatex -interaction=nonstopmode paper.tex || true
	@test -f $(PAPER_DIR)/paper.pdf && echo "Built $(PAPER_DIR)/paper.pdf" || (echo "FAIL: paper.pdf not produced" && false)

# --- arXiv submission zip ---

arxiv: paper
	rm -rf $(ARXIV_DIR) $(ARXIV_ZIP)
	mkdir -p $(ARXIV_DIR)/figures
	cp $(PAPER_DIR)/paper.tex $(ARXIV_DIR)/
	cp $(PAPER_DIR)/paper.bbl $(ARXIV_DIR)/
	cp $(PAPER_DIR)/bibliography.bib $(ARXIV_DIR)/
	cp $(PAPER_DIR)/figures/*.pdf $(ARXIV_DIR)/figures/
	# Inline .bbl so arXiv doesn't need bibtex
	sed -i.bak 's|\\bibliography{bibliography}|\\input{paper.bbl}|' $(ARXIV_DIR)/paper.tex
	rm -f $(ARXIV_DIR)/paper.tex.bak
	# Verify it compiles standalone
	cd $(ARXIV_DIR) && pdflatex -interaction=nonstopmode paper.tex > /dev/null 2>&1 || true
	cd $(ARXIV_DIR) && pdflatex -interaction=nonstopmode paper.tex > /dev/null 2>&1 || true
	# Create zip (arXiv prefers zip)
	cd $(ARXIV_DIR) && zip -r ../$(ARXIV_ZIP) paper.tex paper.bbl bibliography.bib figures/
	@echo "Created $(ARXIV_ZIP) ($$(du -h $(ARXIV_ZIP) | cut -f1))"

# --- Figures ---

figures:
	uv run python -m evals.generate_figures

# --- Tests ---

test:
	uv run pytest -v

# --- Evaluation ---

eval:
	uv run python -m evals.run_eval --option B --use-ner

# --- Clean ---

clean:
	rm -rf $(ARXIV_DIR) $(ARXIV_ZIP)
	rm -f $(PAPER_DIR)/paper.{aux,bbl,blg,log,out,pdf,fls,fdb_latexmk,synctex.gz}
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache
