# LVDAndro (Labelled Vulnerability Dataset on Android Source Code)

Many of the Android apps get published without appropriate security considerations, possibly due to not verifying code or not identifying vulnerabilities at the early stages of development. 

This can be overcome by using an AI based model trained on a properlly labeled dataset. Hence, LVDAndro provides a dataset for Android source code vulnerabilities, labelled based on Common Weakness Enumeration (CWE). 

The dataset has been generated using code lines scanned from real-world Android apps containing a large amount of distinct source code samples.

The dataset can be downloaded from the Dataset directory. There are 3 dataset folders and each contains a readme file with important details and links to download dataset stored in a Google Drive.

If you are using this dataset in your research work, please cite as:
_**Senanayake, J.; Kalutarage, H.; Al-Kadri, M.; Piras, L. and Petrovski, A. (2023). Labelled Vulnerability Dataset on Android Source Code (LVDAndro) to Develop AI-Based Code Vulnerability Detection Models. In Proceedings of the 20th International Conference on Security and Cryptography - SECRYPT; ISBN 978-989-758-666-8; ISSN 2184-7711, SciTePress, pages 659-666. DOI: [10.5220/0012060400003555](https://doi.org/10.5220/0012060400003555)**_


## Sub-datasets of LVDAndro

![LVDAndro_datasets](https://user-images.githubusercontent.com/102326773/196053837-a9cf7490-1ac1-49b6-a8f8-9ffca6b1a25d.png)

### An Auto ML based model has been trained with LVDAndro and it achieved 94\% accuracy in both binary and multi-class classification with 0.94 and 0.93 F1-Score, respecitively, in each classification approach.


## Dataset Generation Process :

The scripts in the Dataset Geneation Scripts directory contains the python scripts to extend/ re-create dataset. The overall dataset generation process is illustrated as follow.

![LVDAndro](https://user-images.githubusercontent.com/102326773/196053776-3b763757-259f-47e9-8c82-9a0e1d3afbec.png)



