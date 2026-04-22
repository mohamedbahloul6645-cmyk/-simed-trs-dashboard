"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   DASHBOARD TRS/OEE – SIMED  v6.0 (PROFESSIONNEL)                          ║
║   Authentification + Base SQLite + Import intelligent + Prévisions         ║
║   Tableau de bord avec jauge OEE et statut machines                        ║
║   Logo : simed-200x200-1.png                                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime, timedelta, date
import sqlite3, os, io, warnings, hashlib, secrets
from sklearn.linear_model import LinearRegression
warnings.filterwarnings('ignore')

# ══════════════════════════════════════════════════════════════
# PAGE CONFIG
# ══════════════════════════════════════════════════════════════
st.set_page_config(page_title="TRS/OEE – SIMED", page_icon="⚙️", layout="wide", initial_sidebar_state="expanded")

# ══════════════════════════════════════════════════════════════
# BASE DE DONNÉES SQLITE (production + users)
# ══════════════════════════════════════════════════════════════
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "simed_database.db")

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_db():
    with get_conn() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS production (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            date_jour            TEXT    NOT NULL,
            semaine              INTEGER,
            ligne                TEXT,
            code_machine         TEXT,
            type_machine         TEXT,
            operateur            TEXT,
            code_probleme        TEXT,
            categorie_panne      TEXT,
            categorie_iso        TEXT,
            departement_resp     TEXT,
            description_probleme TEXT,
            temps_arret          REAL DEFAULT 0,
            produit              TEXT,
            quantite             REAL DEFAULT 0,
            rebuts               REAL DEFAULT 0,
            created_at           TEXT DEFAULT (datetime('now'))
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            created_at    TEXT DEFAULT (datetime('now'))
        )""")
        cursor = conn.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            salt = secrets.token_hex(16)
            pwd = "SIMED2025"
            hash_obj = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt.encode(), 100000)
            password_hash = hash_obj.hex()
            conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                         ("admin", password_hash, salt))
            conn.commit()
init_db()

# ══════════════════════════════════════════════════════════════
# AUTHENTIFICATION
# ══════════════════════════════════════════════════════════════
def hash_password(password, salt):
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hash_obj.hex()

def verify_password(username, password):
    with get_conn() as conn:
        cursor = conn.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row is None:
            return False
        stored_hash, salt = row
        return hash_password(password, salt) == stored_hash

def register_user(username, password):
    if not username or not password:
        return False, "Nom d'utilisateur et mot de passe requis."
    if len(password) < 6:
        return False, "Le mot de passe doit contenir au moins 6 caractères."
    with get_conn() as conn:
        cursor = conn.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            return False, "Ce nom d'utilisateur existe déjà."
        salt = secrets.token_hex(16)
        password_hash = hash_password(password, salt)
        conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                     (username, password_hash, salt))
        conn.commit()
        return True, "Inscription réussie. Vous pouvez maintenant vous connecter."

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

def login_signup_page():
    st.markdown("""
        <style>
        .login-container {
            max-width: 480px;
            margin: 8% auto;
            padding: 2rem;
            background: white;
            border-radius: 24px;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1);
        }
        .login-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            text-align: center;
            color: #0f172a;
        }
        </style>
    """, unsafe_allow_html=True)
    with st.container():
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        st.markdown('<div class="login-title">🔐 SIMED TRS Dashboard</div>', unsafe_allow_html=True)
        tab1, tab2 = st.tabs(["🔑 Connexion", "📝 Inscription"])
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Nom d'utilisateur", placeholder="admin")
                password = st.text_input("Mot de passe", type="password", placeholder="•••••••")
                col1, col2 = st.columns([1,1])
                with col1:
                    submitted = st.form_submit_button("Se connecter", use_container_width=True)
                with col2:
                    demo = st.form_submit_button("Invité (démo)", use_container_width=True)
                if submitted:
                    if verify_password(username, password):
                        st.session_state["authenticated"] = True
                        st.session_state["username"] = username
                        st.rerun()
                    else:
                        st.error("❌ Identifiants incorrects")
                if demo:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = "invité"
                    st.rerun()
        with tab2:
            with st.form("signup_form"):
                new_user = st.text_input("Choisissez un nom d'utilisateur", placeholder="ex: jean.dupont")
                new_pass = st.text_input("Choisissez un mot de passe", type="password", placeholder="au moins 6 caractères")
                confirm_pass = st.text_input("Confirmez le mot de passe", type="password")
                signup_btn = st.form_submit_button("Créer mon compte", use_container_width=True)
                if signup_btn:
                    if new_pass != confirm_pass:
                        st.error("❌ Les mots de passe ne correspondent pas.")
                    else:
                        ok, msg = register_user(new_user, new_pass)
                        if ok:
                            st.success(msg)
                            st.info("Vous pouvez maintenant vous connecter avec votre compte.")
                        else:
                            st.error(f"❌ {msg}")
        st.markdown('</div>', unsafe_allow_html=True)

if not st.session_state["authenticated"]:
    login_signup_page()
    st.stop()

# ══════════════════════════════════════════════════════════════
# FONCTIONS PRODUCTION
# ══════════════════════════════════════════════════════════════
def load_db():
    with get_conn() as conn:
        df = pd.read_sql("SELECT * FROM production ORDER BY date_jour DESC", conn)
    if not df.empty:
        df['date_jour'] = pd.to_datetime(df['date_jour'])
    return df

def insert_row(row: dict):
    cols = [c for c in row if c != 'id']
    ph = ", ".join(["?"] * len(cols))
    sql = f"INSERT INTO production ({', '.join(cols)}) VALUES ({ph})"
    with get_conn() as conn:
        conn.execute(sql, [row[c] for c in cols])
        conn.commit()

def delete_row(row_id: int):
    with get_conn() as conn:
        conn.execute("DELETE FROM production WHERE id=?", (row_id,))
        conn.commit()

def import_df_to_db(df: pd.DataFrame):
    df2 = df.copy()
    df2['date_jour'] = pd.to_datetime(df2['date_jour']).dt.strftime('%Y-%m-%d')
    if 'semaine' not in df2.columns:
        df2['semaine'] = pd.to_datetime(df2['date_jour']).apply(lambda d: int(datetime.strptime(d,'%Y-%m-%d').isocalendar()[1]))
    needed = ['date_jour','semaine','ligne','code_machine','type_machine','operateur',
              'code_probleme','categorie_panne','categorie_iso','departement_resp',
              'description_probleme','temps_arret','produit','quantite','rebuts']
    for c in needed:
        if c not in df2.columns:
            df2[c] = 'N/A' if c not in ['temps_arret','quantite','rebuts','semaine'] else 0
    with get_conn() as conn:
        df2[needed].to_sql('production', conn, if_exists='append', index=False)
        conn.commit()
    return len(df2)

# ══════════════════════════════════════════════════════════════
# IMPORT INTELLIGENT (détection automatique des en-têtes)
# ══════════════════════════════════════════════════════════════
def detect_header_row(df_raw, required_cols):
    for i, row in df_raw.iterrows():
        cells = [str(cell).strip().lower() for cell in row.values]
        if all(col.lower() in cells for col in required_cols):
            return i
    return None

def load_uploaded_file(uploaded_file):
    try:
        if uploaded_file.name.endswith('.csv'):
            df_raw = pd.read_csv(uploaded_file, header=None)
        else:
            df_raw = pd.read_excel(uploaded_file, header=None)
        required = ['date_jour', 'quantite', 'temps_arret']
        header_row = detect_header_row(df_raw, required)
        if header_row is None:
            return None, "Impossible de trouver la ligne d'en-tête contenant les colonnes requises."
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file, skiprows=header_row)
        else:
            df = pd.read_excel(uploaded_file, skiprows=header_row)
        return df, None
    except Exception as e:
        return None, str(e)

# ══════════════════════════════════════════════════════════════
# LOGO (statique)
# ══════════════════════════════════════════════════════════════
LOGO_PATH = "simed-200x200-1.png"   # Utilisez votre fichier logo
def afficher_logo(emplacement="sidebar", largeur=120):
    if os.path.exists(LOGO_PATH):
        if emplacement == "sidebar":
            st.sidebar.image(LOGO_PATH, width=largeur)
        else:
            st.image(LOGO_PATH, width=largeur)
    else:
        if emplacement == "sidebar":
            st.sidebar.warning("Logo non trouvé (simed-200x200-1.png)")

# ══════════════════════════════════════════════════════════════
# CSS (thème clair)
# ══════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;600&display=swap');
html,body,[class*="css"]{ font-family: 'IBM Plex Sans', sans-serif; font-size: 16px; color: #1e293b; }
.stApp{ background: #f8fafc; }
section[data-testid="stSidebar"]{ background: #ffffff !important; border-right: 1px solid #e2e8f0; }
h1, h2, h3, h4, h5, h6{ color: #0f172a !important; font-weight: 600 !important; }
div[data-testid="metric-container"]{ background: #ffffff; border: 1px solid #e2e8f0; border-top: 3px solid #3b82f6; border-radius: 12px; padding: 1rem !important; }
div[data-testid="metric-container"] label{ font-family: 'IBM Plex Mono', monospace; font-size: 0.75rem !important; color: #475569; text-transform: uppercase; }
div[data-testid="metric-container"] [data-testid="stMetricValue"]{ font-size: 2rem !important; font-weight: 700; color: #0f172a; }
.sh{ font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; letter-spacing: 0.1em; text-transform: uppercase; color: #3b82f6; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin: 32px 0 16px; display: flex; align-items: center; gap: 8px; }
.sh::before{ content: ''; display: inline-block; width: 4px; height: 18px; background: #3b82f6; border-radius: 2px; }
.badge-ok{ background: #dcfce7; color: #15803d; border: 1px solid #86efac; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
.badge-warn{ background: #fef9c3; color: #854d0e; border: 1px solid #fde047; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
.badge-alert{ background: #fee2e2; color: #b91c1c; border: 1px solid #fca5a5; padding: 4px 12px; border-radius: 20px; font-weight: 600; }
.ib, .wb, .ab, .sb{ border-radius: 8px; padding: 12px 16px; font-size: 0.9rem; margin: 8px 0; }
.ib{ background: #f1f5f9; border-left: 4px solid #3b82f6; color: #1e293b; }
.wb{ background: #fffbeb; border-left: 4px solid #eab308; color: #78350f; }
.ab{ background: #fef2f2; border-left: 4px solid #ef4444; color: #7f1d1d; }
.sb{ background: #dcfce7; border-left: 4px solid #22c55e; color: #14532d; }
.stTabs [data-baseweb="tab-list"]{ background: #ffffff; border-bottom: 1px solid #e2e8f0; }
.stTabs [data-baseweb="tab"]{ font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; font-weight: 500; color: #475569; padding: 10px 20px; border-bottom: 2px solid transparent; }
.stTabs [aria-selected="true"]{ color: #3b82f6 !important; border-bottom: 2px solid #3b82f6 !important; }
.stDataFrame{ border: 1px solid #e2e8f0; border-radius: 12px; }
.stDownloadButton button{ background: #eff6ff !important; color: #1e40af !important; border: 1px solid #bfdbfe !important; font-family: 'IBM Plex Mono', monospace !important; border-radius: 20px !important; }
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════
# THÈME PLOTLY CLAIR
# ══════════════════════════════════════════════════════════════
PL = dict(
    paper_bgcolor='#ffffff', plot_bgcolor='#f8fafc',
    font=dict(family='IBM Plex Sans, sans-serif', color='#1e293b', size=13),
    xaxis=dict(gridcolor='#e2e8f0', linecolor='#cbd5e1', tickfont=dict(size=11)),
    yaxis=dict(gridcolor='#e2e8f0', linecolor='#cbd5e1', tickfont=dict(size=11)),
    legend=dict(bgcolor='#ffffff', bordercolor='#e2e8f0', borderwidth=1),
    margin=dict(l=50, r=30, t=60, b=40),
    title_font=dict(size=15, color='#0f172a')
)
C = {'trs':'#3b82f6','dispo':'#10b981','perf':'#f59e0b','qual':'#8b5cf6','rebut':'#ef4444','alert':'#f97316'}

# ══════════════════════════════════════════════════════════════
# RÉFÉRENCES
# ══════════════════════════════════════════════════════════════
LIGNES = ['Ligne A','Ligne B','Ligne C']
MACHINES = ['M01','M02','M03','MA01','MA02','MB01','MB02','MC01','MC02']
TYPES_MACH = ['Presse','Remplisseuse','Mélangeuse','Encapsuleuse','Scelleuse','Étiqueteuse','Compression','Conditionnement']
CODES_PROB = {
    'E01':('Électrique','Défaut capteur','Breakdown','Maintenance'),
    'E02':('Électrique','Bande transporteuse bloquée','Breakdown','Maintenance'),
    'M02':('Mécanique','Surcharge moteur','Breakdown','Maintenance'),
    'M03':('Mécanique','Usure palier roulement','Breakdown','Maintenance'),
    'P03':('Process','Problème thermique','Process','Production'),
    'P04':('Process','Hors-spécification temp.','Process','Qualité'),
    'R04':('Réglage','Réglage outil','Setup','Production'),
    'R05':('Réglage','Changement format produit','Setup','Production'),
    'Q06':('Qualité','Contrôle IPC non-conforme','Quality','Qualité'),
    'A05':('Appro','Manque matière','Material','Logistique'),
    'A07':('Appro','Rupture matière première','Material','Logistique'),
    'U08':('Utilités','Air comprimé faible','Breakdown','Maintenance'),
}
PRODUITS = ['Comprimé 500mg','Sirop 125mg/5mL','Gélule 250mg','Pommade 1%','Sirop Y','Gélule Z','Pommade W']
OPERATEURS = ['Karim B.','Amira T.','Sami L.','Nadia M.','Youssef R.','Sophie','Jean','Marie','Pierre','Ahmed']

# ══════════════════════════════════════════════════════════════
# FONCTIONS TRS
# ══════════════════════════════════════════════════════════════
def compute_trs(df_in, TO, cadence):
    Tc = 1.0 / max(0.001, cadence)
    g = df_in.groupby(['date_jour','ligne','code_machine','produit','operateur']).agg(
        total_arret=('temps_arret','sum'), quantite_totale=('quantite','sum'),
        rebuts_totaux=('rebuts','sum'), nb_incidents=('temps_arret',lambda x:(x>0).sum())
    ).reset_index()
    g['TF'] = (TO - g['total_arret']).clip(lower=0)
    g['disponibilite'] = (g['TF'] / TO).clip(0,1)
    g['performance'] = ((g['quantite_totale']*Tc) / g['TF'].clip(lower=1)).clip(0,1)
    g['conformes'] = (g['quantite_totale']-g['rebuts_totaux']).clip(lower=0)
    g['qualite'] = np.where(g['quantite_totale']>0, g['conformes']/g['quantite_totale'], 1.0).clip(0,1)
    g['trs'] = (g['disponibilite']*g['performance']*g['qualite']).clip(0,1)
    g['perte_dispo'] = (1-g['disponibilite'])*TO
    g['perte_perf'] = g['disponibilite']*(1-g['performance'])*TO
    g['perte_qual'] = g['disponibilite']*g['performance']*(1-g['qualite'])*TO
    return g

def compute_kpis(df_in, daily, TO, cadence):
    sm = lambda s: s.mean() if len(s)>0 else 0
    tp = df_in['quantite'].sum(); tr = df_in['rebuts'].sum()
    ta = df_in['temps_arret'].sum(); nj = max(1,df_in['date_jour'].nunique())
    ni = (df_in['temps_arret']>0).sum()
    TF = max(0, nj*TO - ta)
    dpmo = (tr/max(1,tp))*1_000_000
    sigma = max(0,min(6, 0.8406+np.sqrt(29.37-2.221*np.log(max(1,dpmo)))))
    return {
        'trs':sm(daily['trs']),'dispo':sm(daily['disponibilite']),
        'perf':sm(daily['performance']),'qual':sm(daily['qualite']),
        'total_produit':tp,'total_rebuts':tr,'taux_rebut':(tr/tp*100) if tp>0 else 0,
        'total_arret':ta,'nb_incidents':ni,'nb_jours':nj,
        'mtbf':TF/ni if ni>0 else 0,'mttr':ta/ni if ni>0 else 0,
        'taux_panne':ni/nj if nj>0 else 0,
        'prod_horaire':max(0,tp-tr)/max(0.001,TF/60),
        'sigma':sigma,'dpmo':dpmo,
        'perte_dispo':sm(daily['perte_dispo']),'perte_perf':sm(daily['perte_perf']),'perte_qual':sm(daily['perte_qual']),
    }

def validate_and_clean(df):
    errs, warns = [], []
    required = ['date_jour', 'quantite', 'temps_arret']
    missing = [c for c in required if c not in df.columns]
    if missing:
        errs.append(f"Colonnes obligatoires manquantes : {missing}.")
        return df, errs, warns
    df['date_jour'] = pd.to_datetime(df['date_jour'], errors='coerce')
    nb_invalid = df['date_jour'].isna().sum()
    if nb_invalid:
        warns.append(f"{nb_invalid} date(s) invalide(s). Elles seront ignorées.")
        df = df.dropna(subset=['date_jour'])
    for col in ['quantite', 'temps_arret']:
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).clip(lower=0)
    if 'rebuts' not in df.columns:
        df['rebuts'] = 0
        warns.append("Colonne 'rebuts' absente → 0 par défaut.")
    else:
        df['rebuts'] = pd.to_numeric(df['rebuts'], errors='coerce').fillna(0).clip(lower=0)
        df['rebuts'] = df[['rebuts', 'quantite']].min(axis=1)
    defaults = {
        'ligne': 'Non défini', 'code_machine': 'N/A', 'type_machine': 'N/A',
        'operateur': 'N/A', 'code_probleme': 'N/A', 'categorie_panne': 'N/A',
        'categorie_iso': 'N/A', 'departement_resp': 'N/A', 'description_probleme': 'N/A',
        'produit': 'N/A'
    }
    for col, default in defaults.items():
        if col not in df.columns:
            df[col] = default
            warns.append(f"Colonne '{col}' absente → '{default}'.")
    if 'semaine' not in df.columns:
        df['semaine'] = df['date_jour'].dt.isocalendar().week.astype(int)
    return df, errs, warns

def forecast_trs(daily_trs, jours=7):
    if len(daily_trs) < 3:
        return None, None
    X = np.arange(len(daily_trs)).reshape(-1,1)
    y = daily_trs.values
    model = LinearRegression()
    model.fit(X, y)
    future_X = np.arange(len(daily_trs), len(daily_trs)+jours).reshape(-1,1)
    pred = model.predict(future_X)
    return pred, model

def generer_rapport_html(kpis, daily, sd, ed, src_label):
    html = f"""
    <html>
    <head><meta charset="UTF-8"><title>Rapport TRS SIMED</title>
    <style>
        body {{ font-family: 'IBM Plex Sans', sans-serif; background: #f8fafc; color: #1e293b; padding: 20px; }}
        h1 {{ color: #0f172a; }}
        .metric {{ background: white; border-radius: 12px; padding: 12px; margin: 10px; border-top: 3px solid #3b82f6; display: inline-block; width: 200px; }}
        .value {{ font-size: 28px; font-weight: bold; color: #0f172a; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 8px; text-align: left; }}
        th {{ background: #f1f5f9; }}
    </style>
    </head>
    <body>
    <h1>📊 Rapport TRS SIMED</h1>
    <p>Période : {sd} → {ed} | Source : {src_label}</p>
    <div>
        <div class="metric">TRS Global<br><span class="value">{kpis['trs']*100:.1f}%</span></div>
        <div class="metric">Disponibilité<br><span class="value">{kpis['dispo']*100:.1f}%</span></div>
        <div class="metric">Performance<br><span class="value">{kpis['perf']*100:.1f}%</span></div>
        <div class="metric">Qualité<br><span class="value">{kpis['qual']*100:.1f}%</span></div>
        <div class="metric">Production<br><span class="value">{kpis['total_produit']:,.0f}</span></div>
        <div class="metric">Taux rebut<br><span class="value">{kpis['taux_rebut']:.2f}%</span></div>
        <div class="metric">Sigma<br><span class="value">{kpis['sigma']:.2f}σ</span></div>
    </div>
    <h2>📈 Évolution quotidienne du TRS</h2>
    <table>
        <tr><th>Date</th><th>TRS (%)</th><th>Dispo (%)</th><th>Perf (%)</th><th>Qualité (%)</th></tr>
    """
    for _, row in daily.iterrows():
        html += f"<tr><td>{row['date_jour'].date()}</td><td>{row['trs']*100:.1f}</td><td>{row['disponibilite']*100:.1f}</td><td>{row['performance']*100:.1f}</td><td>{row['qualite']*100:.1f}</td></tr>"
    html += "</table></body></html>"
    return html

# ══════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════
with st.sidebar:
    afficher_logo("sidebar", 150)
    st.markdown("### ⚙️ TRS / OEE DASHBOARD")
    st.markdown(f'<div style="font-family:IBM Plex Mono,monospace;font-size:0.7rem;color:#3b82f6;">👤 Connecté : {st.session_state["username"]}</div>', unsafe_allow_html=True)
    if st.button("🔓 Déconnexion", use_container_width=True):
        st.session_state["authenticated"] = False
        st.session_state.pop("username", None)
        st.rerun()
    st.markdown("---")
    df_db = load_db()
    nb_db = len(df_db)
    box_cls = "sb" if nb_db > 0 else "wb"
    st.markdown(f'<div class="{box_cls}">{"✅" if nb_db>0 else "⚠️"} <b>{nb_db:,} enregistrement(s)</b><br><span style="font-size:0.75rem;">📁 simed_database.db</span></div>', unsafe_allow_html=True)
    col_r1, col_r2 = st.columns(2)
    with col_r1:
        if st.button("↺ Rafraîchir"):
            st.cache_data.clear()
            st.rerun()
    with col_r2:
        if nb_db > 0:
            st.download_button("📥 Export DB", df_db.to_csv(index=False).encode('utf-8'), "simed_database.csv","text/csv")
    st.markdown("---")
    st.markdown("##### 📂 IMPORTER UN FICHIER")
    uploaded = st.file_uploader("Excel ou CSV (avec ou sans titres)", type=["xlsx","xls","csv"])
    if uploaded:
        if st.button("➕ Importer dans la base", use_container_width=True):
            with st.spinner("Analyse du fichier..."):
                df_imp, err = load_uploaded_file(uploaded)
                if err:
                    st.error(f"❌ Erreur de lecture : {err}")
                else:
                    df_imp, errs, warns = validate_and_clean(df_imp)
                    if errs:
                        for e in errs:
                            st.error(f"❌ {e}")
                    if warns:
                        for w in warns:
                            st.warning(f"⚠️ {w}")
                    if not errs:
                        n = import_df_to_db(df_imp)
                        st.success(f"✅ {n} lignes importées avec succès !")
                        st.rerun()
    st.markdown("---")
    st.markdown("##### 📄 MODÈLE CSV")
    csv_template = """date_jour,ligne,code_machine,operateur,produit,quantite,rebuts,temps_arret,code_probleme,description_probleme
2026-04-21,Ligne A,M01,Jean,Comprimé 500mg,12500,150,45,E01,Défaut capteur
2026-04-22,Ligne B,MB02,Marie,Sirop 125mg/5mL,8200,98,30,P03,Problème thermique"""
    st.download_button("📎 Télécharger modèle CSV", csv_template, "modele_import.csv", "text/csv")
    st.markdown("---")
    st.markdown("##### ⚙️ PARAMÈTRES TRS")
    TO = st.number_input("Temps d'ouverture (min/jour)", 60, 1440, 480, 30)
    CAD = st.number_input("Cadence nominale (u/min)", 1, 9999, 50, 5)
    Tc = 1.0 / max(0.001, CAD)
    st.markdown(f'<div class="ib">Tc = {Tc:.4f} min/u<br>Prod.max = {TO*CAD:,.0f} u/shift</div>', unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("##### 🚨 SEUILS")
    c1, c2 = st.columns(2)
    S_TRS = c1.number_input("TRS min (%)", 0, 100, 60)
    S_DISPO = c2.number_input("Dispo min (%)", 0, 100, 70)
    S_ARRET = st.number_input("Arrêts max/jour (min)", 0, 1440, 120)
    S_REBUT = st.number_input("Taux rebut max (%)", 0.0, 100.0, 3.0, 0.5)
    st.markdown("---")
    st.markdown("##### 🔍 SOURCE & FILTRES")
    source = st.radio("Source", ["🗄️ Base de données","🔵 Données démo"], horizontal=True)
    if source == "🗄️ Base de données":
        df_raw = df_db.copy()
        src_label = f"🗄️ DB ({nb_db} enreg.)"
        if df_raw.empty:
            st.warning("Base vide — utilisez Données démo ou importez un fichier")
    else:
        @st.cache_data
        def load_demo():
            np.random.seed(42)
            dates = pd.date_range('2026-01-01','2026-04-20',freq='D')
            rows = []
            for d in dates:
                for _ in range(np.random.randint(4,10)):
                    lg = np.random.choice(LIGNES)
                    mc = np.random.choice(MACHINES[:6])
                    cp = np.random.choice(list(CODES_PROB.keys()))
                    cat,desc,iso,dept = CODES_PROB[cp]
                    arr = np.random.randint(5,90)
                    tf_ = max(1,480-arr)
                    q = max(0,int(np.random.uniform(0.80,0.97)*50*tf_))
                    reb = int(q*np.random.uniform(0.005,0.04)) if q>0 else 0
                    rows.append({'date_jour':d,'semaine':d.isocalendar().week,'ligne':lg,'code_machine':mc,
                                 'type_machine':np.random.choice(TYPES_MACH),'operateur':np.random.choice(OPERATEURS),
                                 'code_probleme':cp,'categorie_panne':cat,'categorie_iso':iso,
                                 'departement_resp':dept,'description_probleme':desc,'temps_arret':arr,
                                 'produit':np.random.choice(PRODUITS),'quantite':q,'rebuts':reb})
            return pd.DataFrame(rows)
        df_raw = load_demo()
        src_label = "🔵 DÉMO"
    sd, ed = date.today(), date.today()
    df_filt = pd.DataFrame()
    if not df_raw.empty:
        df_raw['date_jour'] = pd.to_datetime(df_raw['date_jour'])
        mn_d = df_raw['date_jour'].min().date()
        mx_d = df_raw['date_jour'].max().date()
        peri = st.selectbox("Période", ["Tout","7 derniers jours","Ce mois","Trimestre","Personnalisé"])
        today_ = date.today()
        if peri=="7 derniers jours": sd,ed = mx_d-timedelta(6),mx_d
        elif peri=="Ce mois":        sd,ed = today_.replace(day=1),today_
        elif peri=="Trimestre":      sd,ed = today_-timedelta(90),today_
        elif peri=="Personnalisé":
            cc1,cc2=st.columns(2); sd=cc1.date_input("Début",mn_d,min_value=mn_d,max_value=mx_d); ed=cc2.date_input("Fin",mx_d,min_value=mn_d,max_value=mx_d)
        else: sd,ed = mn_d,mx_d
        mask = (df_raw['date_jour'].dt.date>=sd) & (df_raw['date_jour'].dt.date<=ed)
        df_filt = df_raw[mask].copy()
        col1, col2 = st.columns(2)
        with col1:
            lignes_opt = sorted(df_filt['ligne'].unique())
            sl = st.multiselect("Lignes", lignes_opt, default=lignes_opt)
            df_filt = df_filt[df_filt['ligne'].isin(sl)]
            machines_opt = sorted(df_filt['code_machine'].unique())
            sm = st.multiselect("Machines", machines_opt, default=machines_opt)
            df_filt = df_filt[df_filt['code_machine'].isin(sm)]
        with col2:
            ops_opt = sorted(df_filt['operateur'].unique())
            so = st.multiselect("Opérateurs", ops_opt, default=ops_opt)
            df_filt = df_filt[df_filt['operateur'].isin(so)]
            prod_opt = sorted(df_filt['produit'].unique())
            sp = st.multiselect("Produits", prod_opt, default=prod_opt)
            df_filt = df_filt[df_filt['produit'].isin(sp)]

# ══════════════════════════════════════════════════════════════
# ONGLETS (11 onglets : TABLEAU DE BORD ajouté en premier)
# ══════════════════════════════════════════════════════════════
tabs = st.tabs(["📊 TABLEAU DE BORD","📈 VUE GLOBALE","📊 ANALYSE TRS","⛔ PANNES","📦 PRODUCTION","🔬 QUALITÉ","🔧 MAINTENANCE",
                "🏷️ PAR PRODUIT","👥 PAR OPÉRATEUR","➕ SAISIE","📋 BASE"])

no_data_msg = '<div class="wb">⚠️ Aucune donnée. Utilisez <b>➕ SAISIE</b> ou <b>Importez un fichier</b>.</div>'

# Calcul des données TRS (si disponibles) pour tous les onglets
if not df_filt.empty:
    daily = compute_trs(df_filt, TO, CAD)
    kpis = compute_kpis(df_filt, daily, TO, CAD)
    
    period_len = max(1,(ed-sd).days)
    prev_sd = sd - timedelta(days=period_len)
    prev_ed = sd - timedelta(days=1)
    df_prev = df_raw[(df_raw['date_jour'].dt.date>=prev_sd) & (df_raw['date_jour'].dt.date<=prev_ed)]
    kpis_prev = {}
    if not df_prev.empty:
        dp = compute_trs(df_prev, TO, CAD)
        kpis_prev = compute_kpis(df_prev, dp, TO, CAD)
    
    def delta(key):
        if not kpis_prev or key not in kpis_prev: return None
        d = kpis[key]-kpis_prev[key]
        if key in ['trs','dispo','perf','qual']: return f"{d*100:+.1f}pp"
        if key=='taux_rebut': return f"{d:+.2f}%"
        return f"{d:+,.0f}"
    
    alertes = []
    if kpis['trs'] < S_TRS/100: alertes.append(('CRIT',f"TRS = {kpis['trs']*100:.1f}% < {S_TRS}%"))
    if kpis['dispo'] < S_DISPO/100: alertes.append(('CRIT',f"Dispo = {kpis['dispo']*100:.1f}% < {S_DISPO}%"))
    if kpis['taux_rebut'] > S_REBUT: alertes.append(('WARN',f"Rebut = {kpis['taux_rebut']:.2f}% > {S_REBUT}%"))
    ov = df_filt.groupby('date_jour')['temps_arret'].sum()
    if (ov > S_ARRET).any(): alertes.append(('WARN',f"{(ov>S_ARRET).sum()} jour(s) arrêts > {S_ARRET} min"))
    
    # En-tête avec logo
    ct, cs = st.columns([3,1])
    with ct:
        col_logo, col_titre = st.columns([1,6])
        with col_logo:
            afficher_logo("main", 60)
        with col_titre:
            st.markdown(f'<div><span style="font-size:1.5rem;font-weight:700;">⚙️ SIMED — TRS / OEE DASHBOARD</span><span style="font-size:0.7rem;margin-left:14px;">ISO 22400-2:2014</span></div><div style="font-size:0.8rem;">📅 {sd} → {ed} | {src_label} | {kpis["nb_jours"]} jours</div>', unsafe_allow_html=True)
    with cs:
        nb_crit = sum(1 for a in alertes if a[0]=='CRIT')
        nb_warn = sum(1 for a in alertes if a[0]=='WARN')
        if nb_crit: st.markdown(f'<div style="text-align:right;"><span class="badge-alert">⛔ {nb_crit} CRITIQUE(S)</span></div>', unsafe_allow_html=True)
        if nb_warn: st.markdown(f'<div style="text-align:right;"><span class="badge-warn">⚠️ {nb_warn} AVERT.</span></div>', unsafe_allow_html=True)
        if not alertes: st.markdown('<div style="text-align:right;"><span class="badge-ok">✅ NOMINAL</span></div>', unsafe_allow_html=True)
    st.markdown("---")

# ──────────────────────────────────────────────────────────────
# ONGLET 0 : TABLEAU DE BORD (jauge + statuts machines)
# ──────────────────────────────────────────────────────────────
with tabs[0]:
    st.markdown('<div class="sh">📊 TABLEAU DE BORD TRS / OEE</div>', unsafe_allow_html=True)
    if df_filt.empty:
        st.info("ℹ️ Aucune donnée disponible. Importez des données ou utilisez la démo.")
    else:
        trs_global = kpis['trs'] * 100
        dispo_global = kpis['dispo'] * 100
        perf_global = kpis['perf'] * 100
        qual_global = kpis['qual'] * 100
        arrets_totaux = kpis['total_arret'] / 60  # heures
        
        # Jauge OEE
        fig_jauge = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = trs_global,
            title = {'text': "OEE (TRS Global)", 'font': {'size': 20}},
            delta = {'reference': 80, 'increasing': {'color': "#10b981"}, 'decreasing': {'color': "#ef4444"}},
            gauge = {
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#1e293b"},
                'bar': {'color': "#3b82f6", 'thickness': 0.3},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "#e2e8f0",
                'steps': [
                    {'range': [0, 60], 'color': '#fee2e2'},
                    {'range': [60, 80], 'color': '#fef9c3'},
                    {'range': [80, 100], 'color': '#dcfce7'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 2},
                    'thickness': 0.75,
                    'value': S_TRS
                }
            }
        ))
        fig_jauge.update_layout(height=300, paper_bgcolor='#ffffff', font={'color': "#0f172a", 'family': "IBM Plex Sans, sans-serif"})
        st.plotly_chart(fig_jauge, use_container_width=True)
        
        # 4 indicateurs clés
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📈 Disponibilité", f"{dispo_global:.1f}%", delta=None)
        with col2:
            st.metric("⚡ Performance", f"{perf_global:.1f}%", delta=None)
        with col3:
            st.metric("🔬 Qualité", f"{qual_global:.1f}%", delta=None)
        with col4:
            st.metric("⏱️ Arrêts totaux", f"{arrets_totaux:.1f} h", delta=None)
        
        # Statut des machines (basé sur le dernier jour)
        st.markdown('<div class="sh">🖥️ STATUT DES MACHINES</div>', unsafe_allow_html=True)
        dernier_jour = df_filt['date_jour'].max()
        arrets_aujourdhui = df_filt[df_filt['date_jour'] == dernier_jour].groupby('code_machine')['temps_arret'].sum()
        machines_uniques = sorted(df_filt['code_machine'].unique())
        nb_cols = 4
        cols_machines = st.columns(nb_cols)
        for i, machine in enumerate(machines_uniques):
            with cols_machines[i % nb_cols]:
                arret = arrets_aujourdhui.get(machine, 0)
                statut = "🟡 Arrêt" if arret > 0 else "🟢 En marche"
                couleur = "#f59e0b" if arret > 0 else "#10b981"
                st.markdown(f"""
                <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:12px; padding:12px; margin:8px 0; text-align:center;">
                    <div style="font-weight:600; font-size:1rem;">{machine}</div>
                    <div style="color:{couleur}; font-weight:500;">{statut}</div>
                </div>
                """, unsafe_allow_html=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 1 : VUE GLOBALE
# ──────────────────────────────────────────────────────────────
with tabs[1]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        for lvl,msg in alertes:
            st.markdown(f'<div class="{"ab" if lvl=="CRIT" else "wb"}">{"⛔" if lvl=="CRIT" else "⚠️"} <b>{lvl}</b> — {msg}</div>', unsafe_allow_html=True)
        st.markdown('<div class="sh">INDICATEURS TRS</div>', unsafe_allow_html=True)
        k1,k2,k3,k4 = st.columns(4)
        k1.metric("TRS GLOBAL", f"{kpis['trs']*100:.1f}%", delta('trs'))
        k2.metric("DISPONIBILITÉ", f"{kpis['dispo']*100:.1f}%", delta('dispo'))
        k3.metric("PERFORMANCE", f"{kpis['perf']*100:.1f}%", delta('perf'))
        k4.metric("QUALITÉ", f"{kpis['qual']*100:.1f}%", delta('qual'))
        st.markdown('<div class="sh">PRODUCTION & SIX SIGMA</div>', unsafe_allow_html=True)
        k1,k2,k3,k4,k5 = st.columns(5)
        k1.metric("PRODUCTION", f"{kpis['total_produit']:,.0f}")
        k2.metric("REBUTS", f"{kpis['total_rebuts']:,.0f}")
        k3.metric("TAUX REBUT", f"{kpis['taux_rebut']:.2f}%")
        k4.metric("PROD/H", f"{kpis['prod_horaire']:,.0f} u")
        k5.metric("NIVEAU SIGMA", f"{kpis['sigma']:.2f} σ")
        st.markdown('<div class="sh">PRÉVISION TRS (7 jours)</div>', unsafe_allow_html=True)
        daily_journalier = daily.groupby('date_jour')[['trs','disponibilite','performance','qualite']].mean().reset_index().sort_values('date_jour')
        pred, model = forecast_trs(daily_journalier['trs'], 7)
        if pred is not None:
            last_date = daily_journalier['date_jour'].max()
            future_dates = [last_date + timedelta(days=i+1) for i in range(7)]
            fig_forecast = go.Figure()
            fig_forecast.add_trace(go.Scatter(x=daily_journalier['date_jour'], y=daily_journalier['trs']*100, mode='lines+markers', name='Historique', line=dict(color=C['trs'])))
            fig_forecast.add_trace(go.Scatter(x=future_dates, y=pred*100, mode='lines+markers', name='Prévision', line=dict(color='#f97316', dash='dot')))
            fig_forecast.add_hline(y=S_TRS, line_dash="dash", line_color="red", annotation_text=f"Seuil {S_TRS}%")
            fig_forecast.update_layout(**PL, height=350, title="Projection TRS sur 7 jours")
            st.plotly_chart(fig_forecast, use_container_width=True)
            st.caption(f"Tendance : {'📈 Hausse' if model.coef_[0]>0 else '📉 Baisse'} de {abs(model.coef_[0]*100):.2f}% par jour en moyenne")
        else:
            st.info("Pas assez de données historiques pour une prévision fiable (≥3 jours requis).")
        st.markdown('<div class="sh">🏆 CLASSEMENT DES MACHINES</div>', unsafe_allow_html=True)
        machine_trs = daily.groupby('code_machine')['trs'].mean().sort_values(ascending=False).reset_index()
        best = machine_trs.head(3)
        worst = machine_trs.tail(3)
        col_best, col_worst = st.columns(2)
        with col_best:
            st.markdown("**✅ Meilleures machines**")
            for _, row in best.iterrows():
                st.markdown(f"- {row['code_machine']} : **{row['trs']*100:.1f}%**")
        with col_worst:
            st.markdown("**⚠️ Machines à améliorer**")
            for _, row in worst.iterrows():
                st.markdown(f"- {row['code_machine']} : **{row['trs']*100:.1f}%**")
        st.markdown('<div class="sh">📥 EXPORT RAPPORT</div>', unsafe_allow_html=True)
        rapport_html = generer_rapport_html(kpis, daily_journalier, sd, ed, src_label)
        st.download_button("📄 Télécharger rapport HTML", rapport_html, "rapport_trs.html", "text/html")

# ──────────────────────────────────────────────────────────────
# ONGLET 2 : ANALYSE TRS
# ──────────────────────────────────────────────────────────────
with tabs[2]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        st.markdown('<div class="sh">ÉVOLUTION TRS + MOYENNE MOBILE</div>', unsafe_allow_html=True)
        td = daily.groupby('date_jour')[['trs','disponibilite','performance','qualite']].mean().reset_index()
        td['MA7'] = td['trs'].rolling(7, min_periods=1).mean()
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=td['date_jour'], y=td['trs']*100, mode='lines', name='TRS', line=dict(color=C['trs'], width=2)))
        fig.add_trace(go.Scatter(x=td['date_jour'], y=td['MA7']*100, mode='lines', name='Moy. mobile (7j)', line=dict(color='#f97316', width=2, dash='dot')))
        fig.add_hline(y=S_TRS, line_dash="dash", line_color="red")
        fig.update_layout(**PL, height=380, title="TRS quotidien avec tendance lissée")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('<div class="sh">TRS PAR MACHINE</div>', unsafe_allow_html=True)
        tm = daily.groupby('code_machine')[['trs','disponibilite','performance','qualite']].mean().reset_index().sort_values('trs')
        fm = go.Figure()
        for col_,nm_,clr_ in [('disponibilite','Dispo',C['dispo']),('performance','Perf',C['perf']),('qualite','Qualité',C['qual'])]:
            fm.add_trace(go.Bar(y=tm['code_machine'], x=tm[col_]*100, name=nm_, orientation='h', marker_color=clr_, opacity=0.8))
        fm.add_trace(go.Scatter(y=tm['code_machine'], x=tm['trs']*100, mode='markers+text', name='TRS', marker=dict(symbol='diamond', size=12, color='#3b82f6'), text=[f"{v*100:.1f}%" for v in tm['trs']], textposition='middle right'))
        fm.add_vline(x=S_TRS, line_dash="dash", line_color="red")
        fm.update_layout(**PL, height=350, title="TRS par machine")
        st.plotly_chart(fm, use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 3 : PANNES
# ──────────────────────────────────────────────────────────────
with tabs[3]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        st.markdown('<div class="sh">PARETO DES PANNES</div>', unsafe_allow_html=True)
        pa = df_filt.groupby(['code_probleme','description_probleme','categorie_panne']).agg(duree_totale=('temps_arret','sum'),nb_occ=('temps_arret','count')).reset_index().sort_values('duree_totale', ascending=False)
        pa['cumul'] = 100 * pa['duree_totale'].cumsum() / pa['duree_totale'].sum()
        fp = make_subplots(specs=[[{"secondary_y": True}]])
        fp.add_trace(go.Bar(x=pa['code_probleme'], y=pa['duree_totale'], name="Durée (min)", marker_color='#10b981'), secondary_y=False)
        fp.add_trace(go.Scatter(x=pa['code_probleme'], y=pa['cumul'], mode='lines+markers', name="Cumul (%)", line=dict(color='#ef4444')), secondary_y=True)
        fp.update_layout(**PL, height=400, title="Pareto des arrêts")
        fp.update_yaxes(title_text="Minutes", secondary_y=False)
        fp.update_yaxes(title_text="Cumul (%)", range=[0,110], ticksuffix="%", secondary_y=True)
        st.plotly_chart(fp, use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 4 : PRODUCTION
# ──────────────────────────────────────────────────────────────
with tabs[4]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        pj = df_filt.groupby('date_jour').agg(quantite=('quantite','sum'), rebuts=('rebuts','sum')).reset_index()
        pj['bonne'] = pj['quantite'] - pj['rebuts']
        fig = go.Figure()
        fig.add_trace(go.Bar(x=pj['date_jour'], y=pj['bonne'], name="Bonne", marker_color=C['dispo']))
        fig.add_trace(go.Bar(x=pj['date_jour'], y=pj['rebuts'], name="Rebuts", marker_color=C['rebut']))
        fig.add_hline(y=TO*CAD, line_dash="dot", line_color="gray", annotation_text="Capacité max")
        fig.update_layout(**PL, barmode='stack', height=360, title="Production quotidienne")
        st.plotly_chart(fig, use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 5 : QUALITÉ
# ──────────────────────────────────────────────────────────────
with tabs[5]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        cs1, cs2 = st.columns([1,2])
        with cs1:
            st.markdown(f'<div style="background:white; border-radius:16px; padding:20px; text-align:center;"><div style="font-size:0.7rem;">NIVEAU SIGMA</div><div style="font-size:3rem; font-weight:700; color:#3b82f6;">{kpis["sigma"]:.2f}σ</div><div>DPMO = {kpis["dpmo"]:,.0f}</div></div>', unsafe_allow_html=True)
        with cs2:
            trj = df_filt.groupby('date_jour').agg(q=('quantite','sum'), r=('rebuts','sum')).reset_index()
            trj['taux'] = (trj['r']/trj['q']*100).fillna(0)
            fig = go.Figure(go.Scatter(x=trj['date_jour'], y=trj['taux'], mode='lines', fill='tozeroy', line=dict(color=C['rebut'])))
            fig.add_hline(y=S_REBUT, line_dash="dash", line_color='orange')
            fig.update_layout(**PL, height=280, title="Taux de rebut journalier", yaxis_title="%")
            st.plotly_chart(fig, use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 6 : MAINTENANCE
# ──────────────────────────────────────────────────────────────
with tabs[6]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        mn = df_filt[df_filt['temps_arret']>0].groupby('code_machine').agg(nb_pannes=('temps_arret','count'), temps_total=('temps_arret','sum')).reset_index()
        mn['MTBF'] = (kpis['nb_jours']*TO - mn['temps_total']) / mn['nb_pannes']
        mn['MTTR'] = mn['temps_total'] / mn['nb_pannes']
        mn = mn.sort_values('MTBF', ascending=False)
        fig = make_subplots(rows=1, cols=2, subplot_titles=("MTBF (min)", "MTTR (min)"))
        fig.add_trace(go.Bar(y=mn['code_machine'], x=mn['MTBF'], orientation='h', marker_color=C['dispo']), row=1, col=1)
        fig.add_trace(go.Bar(y=mn['code_machine'], x=mn['MTTR'], orientation='h', marker_color=C['alert']), row=1, col=2)
        fig.update_layout(**PL, height=340, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 7 : PAR PRODUIT
# ──────────────────────────────────────────────────────────────
with tabs[7]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        st.markdown('<div class="sh">TRS PAR PRODUIT</div>', unsafe_allow_html=True)
        prod_trs = daily.groupby('produit')['trs'].mean().sort_values(ascending=False).reset_index()
        fig = go.Figure(go.Bar(x=prod_trs['produit'], y=prod_trs['trs']*100, marker_color=C['trs']))
        fig.add_hline(y=S_TRS, line_dash="dash", line_color="red")
        fig.update_layout(**PL, height=400, title="TRS moyen par produit", yaxis_title="TRS (%)")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('<div class="sh">DÉTAIL PRODUIT</div>', unsafe_allow_html=True)
        prod_detail = daily.groupby(['date_jour','produit'])['trs'].mean().reset_index()
        pivot_prod = prod_detail.pivot(index='date_jour', columns='produit', values='trs')
        st.dataframe(pivot_prod.style.format("{:.1%}").background_gradient(cmap='RdYlGn', axis=None), use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 8 : PAR OPÉRATEUR
# ──────────────────────────────────────────────────────────────
with tabs[8]:
    if df_filt.empty:
        st.markdown(no_data_msg, unsafe_allow_html=True)
    else:
        st.markdown('<div class="sh">TRS PAR OPÉRATEUR</div>', unsafe_allow_html=True)
        op_trs = daily.groupby('operateur')['trs'].mean().sort_values(ascending=False).reset_index()
        fig = go.Figure(go.Bar(x=op_trs['operateur'], y=op_trs['trs']*100, marker_color=C['trs']))
        fig.add_hline(y=S_TRS, line_dash="dash", line_color="red")
        fig.update_layout(**PL, height=400, title="TRS moyen par opérateur", yaxis_title="TRS (%)")
        st.plotly_chart(fig, use_container_width=True)
        st.markdown('<div class="sh">DÉTAIL OPÉRATEUR</div>', unsafe_allow_html=True)
        op_detail = daily.groupby(['date_jour','operateur'])['trs'].mean().reset_index()
        pivot_op = op_detail.pivot(index='date_jour', columns='operateur', values='trs')
        st.dataframe(pivot_op.style.format("{:.1%}").background_gradient(cmap='RdYlGn', axis=None), use_container_width=True)

# ──────────────────────────────────────────────────────────────
# ONGLET 9 : SAISIE
# ──────────────────────────────────────────────────────────────
with tabs[9]:
    st.markdown('<div class="sh">SAISIE D\'UN NOUVEL ENREGISTREMENT</div>', unsafe_allow_html=True)
    with st.form("saisie_form"):
        col1, col2 = st.columns(2)
        with col1:
            date_saisie = st.date_input("Date", value=date.today())
            ligne_saisie = st.selectbox("Ligne", LIGNES)
            machine_saisie = st.selectbox("Machine", MACHINES)
            operateur_saisie = st.selectbox("Opérateur", OPERATEURS)
            produit_saisie = st.selectbox("Produit", PRODUITS)
        with col2:
            quantite_saisie = st.number_input("Quantité produite", min_value=0, step=100)
            rebuts_saisie = st.number_input("Rebuts", min_value=0, step=10)
            temps_arret_saisie = st.number_input("Temps d'arrêt (min)", min_value=0, step=5)
            code_panne = st.selectbox("Code panne", list(CODES_PROB.keys()))
            desc_panne = st.text_input("Description libre")
        submitted = st.form_submit_button("💾 Enregistrer")
        if submitted:
            cat, desc, iso, dept = CODES_PROB[code_panne]
            insert_row({
                'date_jour': date_saisie.strftime('%Y-%m-%d'),
                'semaine': date_saisie.isocalendar()[1],
                'ligne': ligne_saisie,
                'code_machine': machine_saisie,
                'type_machine': 'N/A',
                'operateur': operateur_saisie,
                'code_probleme': code_panne,
                'categorie_panne': cat,
                'categorie_iso': iso,
                'departement_resp': dept,
                'description_probleme': desc_panne or desc,
                'temps_arret': temps_arret_saisie,
                'produit': produit_saisie,
                'quantite': quantite_saisie,
                'rebuts': rebuts_saisie,
            })
            st.success("✅ Enregistrement ajouté")
            st.rerun()

# ──────────────────────────────────────────────────────────────
# ONGLET 10 : BASE DE DONNÉES
# ──────────────────────────────────────────────────────────────
with tabs[10]:
    st.markdown('<div class="sh">CONTENU DE LA BASE</div>', unsafe_allow_html=True)
    df_view = load_db()
    if df_view.empty:
        st.info("Base vide")
    else:
        st.dataframe(df_view, use_container_width=True)
        if st.button("🗑️ Supprimer toutes les données (CONFIRMER)"):
            with get_conn() as conn:
                conn.execute("DELETE FROM production")
            st.success("Base vidée")
            st.rerun()

# ══════════════════════════════════════════════════════════════
# FOOTER
# ══════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown(f'<div style="text-align:center; font-size:0.7rem; color:#64748b;">SIMED TRS DASHBOARD v6.0 | ISO 22400-2:2014 | {datetime.now().strftime("%Y-%m-%d %H:%M")}</div>', unsafe_allow_html=True)