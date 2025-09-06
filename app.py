from flask import Flask, render_template_string
from crawler import crawl_all_sources

app = Flask(__name__)

@app.route("/")
def index():
    try:
        total = crawl_all_sources()  # 爬蟲回傳抓到幾筆
        return render_template_string("""
            <h2>🛡️ 資安論壇整合爬蟲</h2>
            <p>✅ 爬蟲執行完成，共抓取 {{ total }} 筆。</p>
            <p><a href="/">🔄 重新抓取</a></p>
        """, total=total)
    except Exception as e:
        return f"<h2>❌ 爬蟲錯誤：</h2><pre>{repr(e)}</pre>"

if __name__ == "__main__":
    app.run(debug=True)
