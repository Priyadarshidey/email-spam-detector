EMAIL SECURITY ANALYZER (upgraded Email Spam Detector)
=======================================================
Run:      pip install -r requirements.txt
          python app.py        ->  http://127.0.0.1:5000
Retrain:  python train_model.py   (also rewrites model/metrics.json used by the Dashboard / How It Works pages)

Stack (unchanged): Flask + scikit-learn (TF-IDF -> Multinomial Naive Bayes) + HTML/CSS/JS.
Added: ReportLab (PDF report), Chart.js (bundled in static/vendor, works offline).

Structure
  app.py                  routes + JSON API (/api/analyze, /api/upload, /api/report, /api/model-info)
  services/model_service  wraps the pickled model (probabilities, influential words)
  services/heuristics     rule-based keywords, URL checks, indicators (NOT the ML model)
  services/email_parser   .txt / .eml extraction
  services/report         PDF report
  templates/, static/     pages, css/main.css, js/*.js
  model/original_backup/  your original .pkl files

Notes
  - History is stored in the browser (localStorage).
  - The shipped dataset has only 30 messages, so metrics and predictions are weak.
    Replace spam.csv with a larger dataset (e.g. SMS Spam Collection) and run train_model.py.
  - Add your team details in templates/about.html.
