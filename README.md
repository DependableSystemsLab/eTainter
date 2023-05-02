# eTainter
eTainter is an automated static analysis tool for detecting gas-related vulnerabilities in smart contracts.

For more details about eTainter, please reference the paper published in ISSTA 2022 [eTainter: Detecting Gas-Related Vulnerabilities in Smart Contracts](https://blogs.ubc.ca/dependablesystemslab/2022/04/08/etainter-detecting-gas-related-vulnerabilities-in-smart-contracts)


If you use eTainter, please cite this paper.

 ```
@inproceedings{ghaleb2022etainter,
  title={eTainter: Detecting Gas-Related Vulnerabilities in Smart Contracts},
  author={Ghaleb, Asem and Rubin, Julia and Pattabiraman, Karthik},
  booktitle={Proceedings of the 31st ACM SIGSOFT International Symposium on Software Testing and Analysis},
  year={2022}
}
  ```

## Getting Started
**Note:** We tested all scripts provided in this package on a Ubuntu 18.04 LTS machine.

### Requirements
* Python 3.8+

### Building eTainter 

To build the tool manually, we provide a `requirements.txt` file and the script `setup.py` to simply install the dependencies required by eTainter and to build everything as follows.

Run the following command. Please make sure you are using Python 3.8 or higher.
  
```
cd eTainter
python -m pip install -r requirements.txt
```
 
 ### Analyzing a smart contract
Use the following command to run eTainter on a contract bytecode.
 ```
python bin/analyzer.py -f [path_of_the_contract_bytecode_file] -b
```      
As an example, the following command will analyze the contract file named '*runningExample.code*'
```
python bin/analyzer.py -f runningExample.code -b -m 8
```

The option -m enables setting the allocated memory for the analysis (in gigabytes). In this example, the allocated memory limit is set to 8 GB. The default value is 6 GB when the option -m is not used.

## Contact
For questions about our paper or this code, please contact Asem Ghaleb (aghaleb@alumni.ubc.ca)
