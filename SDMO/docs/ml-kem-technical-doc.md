
# Technical Documentation of ML-KEM by Juuso Koivuranta

## Integration Plan Together With LLM

First iteration of this project had a document proposal of the ML-KEM integration and it can be seen in the ml-kem-migration.md file. The file was used as the only user linked context file to the next LLM.

The ML-KEM codebase intergration to this project was made using Claude Sonnet 5.5 with high thinking effort and maximum context size of 872K tokens through GitHub Copilot. It took the model 2 minutes and 37 seconds to finish the integration plan which can be seen in the ml-kem-infrastructure-plan.md. It spent 24.2 credits in total. The created plan had in total 3672 words which was roughly 16 pages long.


### The following prompt which was inputted to the model to create the plan:

"Study the current legacy edge-cloud software implementation which sends temperature data to the cloud service from a small sensor.
Keep in mind the size of the project and that the project is only a simulation. ML-KEM migration document has a proposal plan which can be used.

Make a step-by-step infrastructure design change plan for the following tasks. Justifications for each choice are necessary.

1. ML-KEM integration: Integrate ML-KEM using an existing
implementation (Python libraries) and specify which existing implementation over the others.

2. Preserve legacy (for example Arduino) compatibility where
appropriate and provide a clearly justified migration and fallback
strategy (Hybrid Implementation).

3. Justify the particular use of a certain ML-KEM version or multiple (1024, 768, 512).

4. Monitoring functionality for the ML-KEM.

5. Design tests that can test the ML-KEM functionality.

6. Consider how the whole wider network infrastructure changes with this integration.

7. Mention alternative post-quantum cryptography approaches to python libraries.


Output a migration plan in plain text. Do not make any code modifications yet."


## Integration Plan Execution Together With LLM
The proposed plan was checked and approved to continue to actual implementation.

The same LLM was used as in the planning phase and in the same session.

It took the model 15 minutes and 48 seconds to make all fundamentally necessary codebase additions to this project and all together it added 2244 new lines of code. It spent 213.7 credits on this implementation.

The LLM also was instructed to compose everything that it built in the session and it can be found in the ml-kem-implementation.md file.