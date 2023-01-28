# CVSS Score Generator

The CVSS score generator is a tool to generate a graphic based on the CVSS scoring of a vulnerability, 
described by a CVSS string. 
It is using the [current version](https://www.first.org/cvss/) published by FIRST, which is v3.1. 
The specification document as a base point for the implementation can be found [here](https://www.first.org/cvss/v3.1/specification-document).

## Usage
### Requirements
Since this project is rather a small one, which should be easy to use and simple, there is no setup.py or other fancy stuff.  
Please make sure to run a more or less up-to-date Python version like 3.7 or above (it's built with 3.10. actually).
You will need the package `matplotlib`, the rest is basic stuff from Python itself. 

### Run
Just use 

```
python main.py <your CVSS vector> <name of the resulting file for the graph>
```

