Ella's Crypto Research

This repository contains my research into cryptographic algorithm design

Layout
----
- crypto
    - dumpasm.py
    - persistence.py
    - utilities.py    
    - analysis 
        - activebits.py
            - tool for measuring diffusion
        - addxortest.py
            - exploring the weak points of addition
        - algebraicnormalform.py
            - "Translate sbox to ANF Boolean functions."; not written by myself
        - branch_number.py
            - tool for measuring diffusion
        - cryptanalysis.py
            - consolidates differential/linear modules to provide a simple "summarize_sbox" method
        - differential.py
            - tools for constructing a difference distribution table
        - linear.py
            - tools for constructing a linear approximation table
        - metrics.py
            - tools for analyzing statistical properties of crypto primitives
        - visualization.py
            - tool for allowing the visual inspection of diffusion over the course of iterating of a function
        - cipherdesign.txt
            - a massive wall of text I wrote for an answer on crypto.se
    - designs            
        - C
            - contains C implementations of some designs
            - folder names are generally design-date (or brief summary of content)   
        - linear
            - contains "linear" cryptography; usually public key crypto, but not always, as some secret key homomorphic designs are present as well 
            - backdoorconvergent
                - exploring convergent encryption with a master key
            - encoding
                - choice and majority encoding ideas that were barely played with
            - homomorphic                    
                - integerbased
                - latticebased                       
                - modexpbased
             - old
                 - initialidea
                 - integerbased
                 - latticebased
                 - publickeyrecipes
                 - xorbased                
            - randomwalk
        - nonlinear
            - contains "nonlinear" cryptography, such as hash functions, block ciphers, and permutations
            - blockcipher
                - arx
                    - I abuse/reappropriate the term to mean (or at least include) And Rotate Xor
                - lightweight
                - sbox
                    - exploring the "class 13 representative" optimal 4x4 s-box
                - standardized ("real"/official ciphers)
                    - AES, speck                                     
            - hash             
            - permutation
                - arxcalibur
                    - Basically the only design that I actually named
            - streamcipher
        - other
            - contains odds and ends that do not fit into the standard crypto design categories    
            - math
            - old
            - scratch           
    - images
        - contains images for explaining certain techniqes/algorithms/ideas
           

Most algorithms/files are simply named according to the design type in an increasing sequence, or are named according to the design type and date.
    
The analysis tools are written in python, as well the designs. A few designs have variants written in C to get a better understanding of algorithm performance on the CPU.
Most of the designs are my own and are not intended for use to protect data in the real world. 

The code is for research purposes. Much of it is effectively scratch paper - the contents of any file are not guaranteed to contain accurate or complete reasoning. Algorithms may be completely broken, and there is usually no warning attached where this is the case.