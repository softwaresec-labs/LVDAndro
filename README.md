# LVDAndro (Labelled Vulnerability Dataset on Android Source Code)

Many of the Android apps get published without appropriate security considerations, possibly due to not verifying code or not identifying vulnerabilities at the early stages of development. 

This can be overcome by using an AI based model trained on a properlly labeled dataset. Hence, LVDAndro provides a dataset for Android source code vulnerabilities, labelled based on Common Weakness Enumeration (CWE). 

The dataset has been generated using code lines scanned from real-world Android apps containing a large amount of distinct source code samples.

The dataset can be downloaded from the Dataset directory. There are 3 dataset folders and each contains a readme file with important details and links to download dataset stored in a Google Drive.

## Sub-datasets of LVDAndro

![LVDAndro_datasets](https://user-images.githubusercontent.com/102326773/196053837-a9cf7490-1ac1-49b6-a8f8-9ffca6b1a25d.png)

### An Auto ML based model has been trained with LVDAndro and it achieved 94\% accuracy in both binary and multi-class classification with 0.94 and 0.93 F1-Score, respecitively, in each classification approach.


## Dataset Generation Process :

The scripts in the Dataset Geneation Scripts directory contains the python scripts to extend/ re-create dataset. The overall dataset generation process is illustrated as follow.

![LVDAndro](https://user-images.githubusercontent.com/102326773/196053776-3b763757-259f-47e9-8c82-9a0e1d3afbec.png)



