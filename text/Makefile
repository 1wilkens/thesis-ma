FILE=thesis.tex
OUTPUT_DIR=tex_out

.PHONY: $(FILE) pdf latexmk copy clean

one-time: pdf copy clean

pdf: $(FILE)
	mkdir -p $(OUTPUT_DIR)/{chapters,misc}
	pdflatex -output-directory=$(OUTPUT_DIR) $(FILE)
	bibtex $(OUTPUT_DIR)/$(FILE:.tex=.aux)
	pdflatex -output-directory=$(OUTPUT_DIR) $(FILE)
	pdflatex -output-directory=$(OUTPUT_DIR) $(FILE)

latexmk: $(FILE)
	mkdir -p $(OUTPUT_DIR)/{chapters,misc}
	latexmk -time -pvc -pdf -new-viewer- -view=pdf -output-directory=$(OUTPUT_DIR) -recorder $<

copy: $(OUTPUT_DIR)/$(FILE:.tex=.pdf)
	cp $(OUTPUT_DIR)/$(FILE:.tex=.pdf) .

clean:
	$(RM) -r $(OUTPUT_DIR)