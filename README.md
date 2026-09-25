# Honeypot Incident Report Generator
1. `pip install -r requirements.txt`
2. `python gen_sample.py`            # creates sample logs (skip if you have real Cowrie logs)
3. `export GEMINI_API_KEY=...`    # optional: change model with LLM_MODEL
4. `streamlit run app.py`

## Real honeypot data (optional)
Run Cowrie in Docker on an ISOLATED cloud VM (never your home/college network):
`docker run -p 2222:2222 cowrie/cowrie`
Use its `var/log/cowrie/cowrie.json` as the input file.
