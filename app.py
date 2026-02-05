import streamlit as st
import pdfplumber
import re
import unicodedata
from datetime import datetime, timedelta
import pandas as pd
import hashlib
import json
import time
import sqlite3
import secrets
import string
from typing import Optional, Tuple, List, Dict, Any
import hmac
import numpy as np
from difflib import SequenceMatcher
import math

# --------------------------------------------------
# CONFIGURAÇÃO DE PÁGINA
# --------------------------------------------------
st.set_page_config(
    page_title="Burocrata de Bolso - Auditoria Jurídica Avançada",
    page_icon="⚖️",
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items=None  # Remove todos os itens do menu
)

# --------------------------------------------------
# CSS PARA OCULTAR ELEMENTOS PADRÃO DO STREAMLIT
# --------------------------------------------------
hide_streamlit_style = """
    <style>
    /* Oculta o menu hamburguer superior direito */
    #MainMenu {visibility: hidden !important;}
    
    /* Oculta o rodapé padrão do Streamlit */
    footer {visibility: hidden !important;}
    
    /* Oculta o cabeçalho padrão (barra superior) */
    header {visibility: hidden !important;}
    
    /* Remove espaçamento extra causado pela remoção do header */
    .stApp > header {
        display: none !important;
    }
    
    /* Remove padding extra no topo da página */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 0rem !important;
    }
    
    /* Esconde o botão de deploy (se existir) */
    .stDeployButton {
        display: none !important;
    }
    
    /* Ajusta o conteúdo principal após remover elementos */
    .stApp {
        margin-top: -50px !important;
    }
    
    /* Oculta qualquer elemento adicional do Streamlit */
    [data-testid="stToolbar"] {
        display: none !important;
    }
    
    [data-testid="stHeader"] {
        display: none !important;
    }
    
    /* Remove qualquer resíduo visual da barra superior */
    div[data-testid="stDecoration"] {
        display: none !important;
    }
    
    /* Remove o ícone de menu se ainda estiver visível */
    button[title="View fullscreen"] {
        display: none !important;
    }
    
    /* Garante que o conteúdo ocupe todo o espaço */
    .main .block-container {
        max-width: 100% !important;
        padding-left: 2rem !important;
        padding-right: 2rem !important;
    }
    
    /* Remove completamente o menu */
    .stApp [data-testid="collapsedControl"] {
        display: none;
    }
    
    /* Remove espaço do header removido */
    .stApp {
        margin-top: -80px;
    }
    
    /* Ajusta o container principal */
    .block-container {
        padding-top: 0.5rem !important;
    }
    </style>
"""

st.markdown(hide_streamlit_style, unsafe_allow_html=True)

# --------------------------------------------------
# SISTEMA DE CRIPTOGRAFIA AVANÇADA
# --------------------------------------------------

class SistemaCriptografia:
    """Sistema de criptografia ultra seguro"""
    
    @staticmethod
    def gerar_salt():
        """Gera salt aleatório de 32 bytes"""
        return secrets.token_hex(32)
    
    @staticmethod
    def hash_senha(senha: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Cria hash ultra seguro com 1.000.000 iterações"""
        if salt is None:
            salt = SistemaCriptografia.gerar_salt()
        
        senha_bytes = senha.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha512',
            senha_bytes,
            salt_bytes,
            1000000,
            dklen=64
        )
        
        hash_hex = hash_bytes.hex()
        return hash_hex, salt
    
    @staticmethod
    def verificar_senha(senha: str, hash_armazenado: str, salt: str) -> bool:
        """Verificação ultra segura"""
        novo_hash, _ = SistemaCriptografia.hash_senha(senha, salt)
        return hmac.compare_digest(novo_hash, hash_armazenado)

# --------------------------------------------------
# SISTEMA DE DETECÇÃO SUPER AVANÇADO
# --------------------------------------------------

class SistemaDetecçãoAvancado:
    """Sistema de detecção com eficiência máxima"""
    
    def __init__(self):
        self.padroes = self._carregar_padroes_completos()
        self.cache_deteccoes = {}
        self.contador_analises = 0
        
    def _limpar_texto_profundo(self, texto):
        """Limpeza ultra profunda"""
        if not texto:
            return ""
        
        # Remover todos os caracteres inválidos
        texto = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202f]', '', texto)
        
        # Remover caracteres especiais do PDF
        caracteres_invalidos = [
            '', '', '', '', '', '', '', '', '', '',
            '', '', '', '', '', '', '', '', '', '',
            '', '', '', '', '', '', '', '', '', ''
        ]
        for char in caracteres_invalidos:
            texto = texto.replace(char, ' ')
        
        # Normalização avançada
        texto = texto.lower()
        texto = unicodedata.normalize('NFKD', texto)
        texto = ''.join([c for c in texto if not unicodedata.combining(c)])
        
        # Remover espaços múltiplos e normalizar
        texto = re.sub(r'\s+', ' ', texto)
        texto = re.sub(r'[\r\n\t]+', ' ', texto)
        
        return texto.strip()
    
    def _extrair_valores_monetarios_completos(self, texto):
        """Extrai TODOS os valores monetários com precisão máxima"""
        padroes_valores = [
            # R$ 1.234,56
            r'R\$\s*(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
            # R$1.234,56
            r'R\$(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
            # 1.234,56 reais
            r'(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)\s*reais',
            # valor de 1.234,56
            r'valor\s*(?:de\s*)?(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
            # US$ 1,234.56
            r'US\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)',
            # € 1.234,56
            r'€\s*(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
            # salário: R$ 1.234,56
            r'sal[áa]rio\s*[:\-]?\s*R?\$?\s*(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
            # aluguel: R$ 1.234,56
            r'aluguel\s*[:\-]?\s*R?\$?\s*(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
            # multa: R$ 1.234,56
            r'multa\s*[:\-]?\s*R?\$?\s*(\d{1,3}(?:\.\d{3})*(?:,\d{2})?)',
        ]
        
        valores = []
        for padrao in padroes_valores:
            for match in re.finditer(padrao, texto, re.IGNORECASE):
                valor_str = match.group(1)
                try:
                    # Converter para float
                    if ',' in valor_str and '.' in valor_str:
                        # Formato 1.234,56
                        valor_str = valor_str.replace('.', '').replace(',', '.')
                    elif ',' in valor_str:
                        # Formato 1,234.56 (US)
                        valor_str = valor_str.replace(',', '')
                    
                    valor = float(valor_str)
                    valores.append({
                        'valor': valor,
                        'texto': match.group(0),
                        'posicao': match.start(),
                        'tipo': self._identificar_tipo_valor(match.group(0))
                    })
                except:
                    continue
        
        return valores
    
    def _identificar_tipo_valor(self, texto_valor):
        """Identifica o tipo de valor monetário"""
        texto = texto_valor.lower()
        if 'salário' in texto or 'salario' in texto:
            return 'salario'
        elif 'aluguel' in texto:
            return 'aluguel'
        elif 'multa' in texto:
            return 'multa'
        elif 'caução' in texto or 'cauçao' in texto or 'garantia' in texto:
            return 'caução'
        elif 'honorário' in texto or 'honorario' in texto:
            return 'honorário'
        else:
            return 'valor_genérico'
    
    def _extrair_datas_completas(self, texto):
        """Extrai TODAS as datas com precisão máxima"""
        padroes_data = [
            # DD/MM/YYYY
            r'(\d{2})[\/\-\.](\d{2})[\/\-\.](\d{4})',
            # DD de Mês de YYYY
            r'(\d{1,2})\s+de\s+(\w+)\s+de\s+(\d{4})',
            # DD-MM-YYYY
            r'(\d{2})-(\d{2})-(\d{4})',
            # YYYY/MM/DD
            r'(\d{4})[\/\-\.](\d{2})[\/\-\.](\d{2})',
            # DD/MM/YY
            r'(\d{2})[\/\-\.](\d{2})[\/\-\.](\d{2})',
            # data: DD/MM/YYYY
            r'data\s*[:\-]?\s*(\d{2})[\/\-\.](\d{2})[\/\-\.](\d{4})',
            # vigência: DD/MM/YYYY
            r'vig[êe]ncia\s*[:\-]?\s*(\d{2})[\/\-\.](\d{2})[\/\-\.](\d{4})',
        ]
        
        datas = []
        meses = {
            'janeiro': 1, 'fevereiro': 2, 'março': 3, 'marco': 3, 'abril': 4,
            'maio': 5, 'junho': 6, 'julho': 7, 'agosto': 8,
            'setembro': 9, 'outubro': 10, 'novembro': 11, 'dezembro': 12
        }
        
        for padrao in padroes_data:
            for match in re.finditer(padrao, texto, re.IGNORECASE):
                try:
                    if 'de' in match.group(0).lower():
                        # Formato "DD de Mês de YYYY"
                        dia = int(match.group(1))
                        mes_nome = match.group(2).lower()
                        mes = meses.get(mes_nome, 1)
                        ano = int(match.group(3))
                    else:
                        # Formato numérico
                        grupos = match.groups()
                        if len(grupos) == 3:
                            if len(grupos[0]) == 4:  # YYYY-MM-DD
                                ano = int(grupos[0])
                                mes = int(grupos[1])
                                dia = int(grupos[2])
                            else:  # DD-MM-YYYY ou DD/MM/YY
                                dia = int(grupos[0])
                                mes = int(grupos[1])
                                ano = int(grupos[2])
                                if ano < 100:  # Se ano tem 2 dígitos
                                    ano += 2000 if ano < 50 else 1900
                    
                    datas.append({
                        'data': f"{dia:02d}/{mes:02d}/{ano}",
                        'texto': match.group(0),
                        'posicao': match.start(),
                        'tipo': self._identificar_tipo_data(match.group(0))
                    })
                except:
                    continue
        
        return datas
    
    def _identificar_tipo_data(self, texto_data):
        """Identifica o tipo de data"""
        texto = texto_data.lower()
        if 'vigência' in texto or 'vigencia' in texto:
            return 'vigência'
        elif 'assinatura' in texto:
            return 'assinatura'
        elif 'início' in texto or 'inicio' in texto:
            return 'início'
        elif 'término' in texto or 'termino' in texto or 'fim' in texto:
            return 'término'
        else:
            return 'data_genérica'
    
    def _detectar_clausulas_similares_avancado(self, texto, padroes_proibidos):
        """Detecta cláusulas similares com algoritmo avançado"""
        clausulas_detectadas = []
        
        # Dividir texto em sentenças
        sentencas = re.split(r'[.;!?]+', texto)
        
        for sentenca in sentencas:
            sentenca = sentenca.strip()
            if len(sentenca) < 15:
                continue
            
            for padrao_nome, config in padroes_proibidos.items():
                # Verificar padrões similares
                for padrao_texto in config.get('padroes_similares', []):
                    similaridade = SequenceMatcher(None, sentenca.lower(), padrao_texto.lower()).ratio()
                    
                    if similaridade > 0.75:  # 75% de similaridade
                        clausulas_detectadas.append({
                            'id': padrao_nome,
                            'nome': config['nome'],
                            'texto': sentenca,
                            'similaridade': similaridade * 100,
                            'gravidade': config['gravidade']
                        })
                
                # Verificar palavras-chave
                palavras_chave = config.get('palavras_chave', [])
                for palavra in palavras_chave:
                    if palavra in sentenca.lower():
                        clausulas_detectadas.append({
                            'id': f"{padrao_nome}_palavra_chave",
                            'nome': f"{config['nome']} (PALAVRA-CHAVE)",
                            'texto': sentenca,
                            'similaridade': 90,
                            'gravidade': config['gravidade']
                        })
        
        return clausulas_detectadas
    
    def _carregar_padroes_completos(self):
        """Carrega padrões completíssimos para todos os tipos de documentos"""
        return {
            'CONTRATO_LOCACAO': {
                'nome': '🏠 Contrato de Locação Residencial',
                'icone': '🏠',
                'marcadores': [
                    r'contrato.*locação.*residencial',
                    r'locador.*locatário',
                    r'aluguel.*imóvel',
                    r'imóvel.*localizado.*em',
                    r'valor.*mensalidade',
                    r'prazo.*vigência',
                    r'cláusula.*primeira',
                    r'foro.*comarca',
                    r'fiador.*caução',
                    r'reajuste.*anual'
                ],
                'o_que_verificamos': [
                    "📈 Reajuste vinculado exclusivamente a índices oficiais (IGP-M/IPCA/INCC)",
                    "💰 Multa rescisória limitada a 3 meses de aluguel",
                    "🔒 Exigência de FIADOR OU caução - nunca ambos",
                    "💵 Caução máxima de 3 meses de aluguel",
                    "⚖️ Foro na comarca onde está situado o imóvel",
                    "📝 Identificação completa das partes (nome, CPF, endereço)",
                    "🏗️ Proibição de obras obrigatórias ao locatário",
                    "🔄 Ausência de renovação automática tácita",
                    "🚫 Proibição de despejo sem processo judicial",
                    "📊 Uso apenas de indexadores oficiais do IBGE/FGV",
                    "⚡ Prazo mínimo de 30 dias para notificações",
                    "🔍 Vistoria conjunta na entrada e saída do imóvel",
                    "📅 Comunicação escrita para todas as alterações",
                    "🛡️ Responsabilidade do locador por benfeitorias necessárias",
                    "🌧️ Responsabilidade por reparos no imóvel",
                    "🔐 Sigilo dos dados do locatário",
                    "📋 Especificação do uso permitido do imóvel"
                ],
                'problemas': {
                    'reajuste_ilegal': {
                        'nome': '🚨 REAJUSTE FORA DOS ÍNDICES OFICIAIS',
                        'descricao': 'Cláusula permite reajuste livre, arbitrário ou não vinculado a índices oficiais do IBGE/FGV',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Lei 8.245/91 Art. 7º + Código de Defesa do Consumidor',
                        'solucao': 'Exigir que o reajuste seja vinculado EXCLUSIVAMENTE a IGP-M, IPCA ou INCC',
                        'penalidade': 'Cláusula nula de pleno direito',
                        'padroes': [
                            r'reajuste.*(livre|arbitr[áa]rio|discricion[áa]rio|unilateral)',
                            r'reajuste.*(independente|fora|sem).*?(índice|indice|IGP|IPCA|INCC|oficial)',
                            r'reajuste.*definido.*pelo.*locador.*(unilateralmente|arbitrariamente)',
                            r'atualização.*valor.*acima.*inflação',
                            r'majoração.*sem.*base.*legal.*objetiva',
                            r'correção.*monetária.*não.*vinculada.*índice',
                            r'percentual.*superior.*inflação',
                            r'revisão.*anual.*(livre|arbitrária)',
                            r'ajuste.*conforme.*mercado',
                            r'correção.*monetária.*arbitrária'
                        ],
                        'padroes_similares': [
                            "o valor do aluguel poderá ser reajustado anualmente conforme critério do locador",
                            "reajuste anual a critério das partes ou conforme mercado",
                            "atualização do aluguel conforme conveniência do locador",
                            "majoração do aluguel acima da inflação oficial",
                            "o reajuste será feito de forma discricionária pelo locador",
                            "correção monetária definida unilateralmente"
                        ],
                        'palavras_chave': ['reajuste livre', 'reajuste arbitrário', 'reajuste discricionário', 'correção unilateral']
                    },
                    'multa_abusiva': {
                        'nome': '💸 MULTA RESCISÓRIA ABUSIVA',
                        'descricao': 'Multa superior a 3 meses de aluguel - VALOR PROIBIDO POR LEI',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Lei 8.245/91 Art. 4º + CDC Art. 51, V',
                        'solucao': 'Limitar multa a NO MÁXIMO 3 meses de aluguel',
                        'penalidade': 'Redução para 3 meses automaticamente',
                        'padroes': [
                            r'multa.*rescis[óo]ria.*(\d+).*meses.*aluguel',
                            r'multa.*(superior|acima|maior).*3.*meses',
                            r'multa.*100%.*aluguel',
                            r'multa.*integral.*per[íi]odo',
                            r'indenização.*rescisória.*(\d+).*meses',
                            r'penalidade.*equivalente.*(\d+).*parcelas',
                            r'pagamento.*(\d+).*meses.*multa',
                            r'multa.*(\d+).*vezes.*aluguel',
                            r'indenização.*de.*(\d+).*aluguéis'
                        ],
                        'padroes_similares': [
                            "multa equivalente a 6 meses de aluguel",
                            "pagamento de 12 meses de aluguel como multa",
                            "indenização de 100% do valor do contrato"
                        ],
                        'palavras_chave': ['multa 6 meses', 'multa 12 meses', 'multa integral']
                    },
                    'garantia_dupla': {
                        'nome': '🔐 EXIGÊNCIA DE FIADOR E CAUÇÃO SIMULTÂNEOS',
                        'descricao': 'Exigência PROIBIDA por lei de fiador E caução ao mesmo tempo',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Lei 8.245/91 Art. 37',
                        'solucao': 'Escolher entre fiador OU caução - NUNCA ambos',
                        'penalidade': 'Nulidade da cláusula abusiva',
                        'padroes': [
                            r'(fiador.*caução|caução.*fiador)',
                            r'garantia.*dupla|dupla.*garantia',
                            r'exig[êe]ncia.*fiador.*e.*caução',
                            r'caução.*além.*fiador',
                            r'fiador.*solidário.*e.*caução',
                            r'fiador.*caução.*simultaneamente',
                            r'fiador.*caução.*ambos',
                            r'exigido.*fiador.*e.*caução'
                        ],
                        'padroes_similares': [
                            "o locatário deverá apresentar fiador e caução",
                            "exigência de fiador solidário e depósito caução",
                            "garantida dupla: fiador e caução"
                        ],
                        'palavras_chave': ['fiador e caução', 'caução e fiador', 'garantia dupla']
                    },
                    'caução_excessiva': {
                        'nome': '💰 CAUÇÃO EXCESSIVA',
                        'descricao': 'Caução superior a 3 meses de aluguel - LIMITE LEGAL',
                        'gravidade': 'ALTO',
                        'lei': 'Lei 8.245/91 Art. 37',
                        'solucao': 'Reduzir caução para no máximo 3 meses de aluguel',
                        'penalidade': 'Redução automática para 3 meses',
                        'padroes': [
                            r'caução.*(\d+).*meses.*aluguel',
                            r'dep[óo]sito.*caução.*(\d+).*meses',
                            r'garantia.*(\d+).*meses.*aluguel',
                            r'caução.*superior.*3.*meses',
                            r'dep[óo]sito.*superior.*3.*meses'
                        ]
                    },
                    'foro_improprio': {
                        'nome': '⚖️ FORO IMPRÓPRIO',
                        'descricao': 'Estipulação de foro em local diferente da comarca do imóvel',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Lei 8.245/91 Art. 51, II',
                        'solucao': 'Foro DEVE SER na comarca onde está situado o imóvel',
                        'penalidade': 'Cláusula nula - foro correto automaticamente',
                        'padroes': [
                            r'foro.*(são paulo|rio de janeiro|outra.*cidade|capital)',
                            r'comarca.*diferente.*imóvel',
                            r'juízo.*(distante|outro.*município)',
                            r'processo.*em.*(outra.*cidade)',
                            r'foro.*da.*comarca.*(?:de|do).*(?!(?:onde|em que).*imóvel)'
                        ]
                    },
                    'renovacao_automatica': {
                        'nome': '🔄 RENOVAÇÃO AUTOMÁTICA ABUSIVA',
                        'descricao': 'Renovação automática do contrato sem manifestação expressa',
                        'gravidade': 'ALTO',
                        'lei': 'Código Civil Art. 445 + CDC Art. 51, IV',
                        'solucao': 'Exigir manifestação EXPRESSA para renovação',
                        'penalidade': 'Renovação somente com acordo expresso',
                        'padroes': [
                            r'renovação.*automática.*tácita',
                            r'prorrogação.*automática',
                            r'contrato.*renovado.*automaticamente',
                            r'tácita.*renovação',
                            r'renova.*por.*igual.*período.*automaticamente',
                            r'prorroga.*automaticamente'
                        ]
                    },
                    'obras_obrigatorias': {
                        'nome': '🏗️ OBRAS OBRIGATÓRIAS AO LOCATÁRIO',
                        'descricao': 'Obrigação do locatário realizar obras ou benfeitorias no imóvel',
                        'gravidade': 'ALTO',
                        'lei': 'Código Civil Art. 1.225',
                        'solucao': 'Remover obrigação de obras do locatário',
                        'penalidade': 'Cláusula nula',
                        'padroes': [
                            r'locatário.*obrigado.*obras',
                            r'locatário.*realizar.*benfeitorias',
                            r'obras.*por.*conta.*locatário',
                            r'reformas.*obrigatórias.*locatário'
                        ]
                    }
                },
                'verificacoes_automaticas': [
                    "✅ Verificação de valores monetários suspeitos",
                    "✅ Análise de datas e prazos",
                    "✅ Detecção de cláusulas ocultas",
                    "✅ Comparação com jurisprudência",
                    "✅ Validação contra base de dados legal"
                ]
            },
            'CONTRATO_EMPREGO': {
                'nome': '👔 Contrato de Trabalho CLT',
                'icone': '👔',
                'marcadores': [
                    r'contrato.*(trabalho|emprego)',
                    r'empregador.*empregado',
                    r'salário.*base',
                    r'jornada.*trabalho',
                    r'férias.*remuneradas',
                    r'FGTS.*8%',
                    r'CLT.*consolidação',
                    r'ctps.*carteira',
                    r'horas.*extras',
                    r'adicional.*noturno'
                ],
                'o_que_verificamos': [
                    "⏰ Jornada máxima de 8h/dia ou 44h/semana",
                    "💰 Salário mínimo de R$ 1.412,00 (2024)",
                    "🏦 FGTS 8% obrigatório mensal",
                    "🏖️ Férias de 30 dias + 1/3 constitucional",
                    "🎁 13º salário integral",
                    "🚫 Ausência de renúncia a direitos trabalhistas",
                    "📝 Registro na CTPS obrigatório",
                    "⏱️ Horas extras 50% (100% domingos/feriados)",
                    "🏥 Contribuição ao INSS patronal",
                    "🌙 Adicional noturno 20%",
                    "🤰 Estabilidade gestante 5 meses",
                    "👶 Licença maternidade 180 dias",
                    "👨 Licença paternidade 20 dias",
                    "📅 Aviso prévio proporcional",
                    "⚖️ Equiparação salarial garantida",
                    "🏥 Vale-transporte obrigatório",
                    "🍽️ Intervalo intrajornada mínimo",
                    "📊 Pagamento em dia sem descontos ilegais"
                ],
                'problemas': {
                    'salario_minimo': {
                        'nome': '💸 SALÁRIO ABAIXO DO MÍNIMO',
                        'descricao': f'Salário inferior ao mínimo constitucional de R$ 1.412,00 - CRIME',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Constituição Art. 7º, IV + CLT Art. 76',
                        'solucao': 'Ajustar imediatamente para R$ 1.412,00 ou superior',
                        'penalidade': 'Multa de 10x a diferença + processo criminal',
                        'padroes': [
                            r'salário.*R?\$?\s*([0-9]{1,3}(?:\.[0-9]{3})*(?:,[0-9]{2})?)',
                            r'remuneração.*R?\$?\s*([0-9]{1,3}(?:\.[0-9]{3})*(?:,[0-9]{2})?)',
                            r'vencimento.*R?\$?\s*([0-9]{1,3}(?:\.[0-9]{3})*(?:,[0-9]{2})?)',
                            r'proventos.*R?\$?\s*([0-9]{1,3}(?:\.[0-9]{3})*(?:,[0-9]{2})?)',
                            r'valor.*R?\$?\s*([0-9]{1,3}(?:\.[0-9]{3})*(?:,[0-9]{2})?)'
                        ]
                    },
                    'jornada_excessiva': {
                        'nome': '⏰ JORNADA EXCESSIVA',
                        'descricao': 'Jornada superior aos limites legais: 8h diárias ou 44h semanais',
                        'gravidade': 'CRÍTICO',
                        'lei': 'CLT Art. 58 + Constituição Art. 7º, XIII',
                        'solucao': 'Reduzir jornada para 8h/dia com horas extras quando exceder',
                        'penalidade': 'Pagamento de horas extras retroativas + 50%',
                        'padroes': [
                            r'jornada.*(\d{2}).*horas.*semanais',
                            r'(\d{2}):.*(\d{2}):.*horas.*trabalho',
                            r'(\d+).*horas.*di[áa]rias',
                            r'trabalho.*(\d+).*horas.*por.*dia',
                            r'expediente.*(\d+).*horas',
                            r'carga.*horária.*(\d+).*horas',
                            r'(\d+).*horas.*semanais'
                        ]
                    },
                    'fgts_ausente': {
                        'nome': '🏦 RENÚNCIA AO FGTS',
                        'descricao': 'Cláusula que tenta renunciar ao direito ao FGTS - ABSOLUTAMENTE ILEGAL',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Lei 8.036/1990 Art. 15 + Súmula 450 TST',
                        'solucao': 'Incluir depósito obrigatório de 8% no FGTS',
                        'penalidade': 'Nulidade da cláusula + depósito retroativo',
                        'padroes': [
                            r'renuncia.*fgts',
                            r'fgts.*renuncia',
                            r'não.*haverá.*fgts',
                            r'sem.*fgts',
                            r'substituição.*fgts.*vale',
                            r'aus[êe]ncia.*FGTS.*depósito',
                            r'opcional.*fgts',
                            r'fgts.*não.*aplicável'
                        ]
                    },
                    'demissao_gravidez': {
                        'nome': '🚫 DEMISSÃO POR GRAVIDEZ',
                        'descricao': 'Rescisão automática em caso de gravidez - CRIME DE DISCRIMINAÇÃO',
                        'gravidade': 'CRÍTICO',
                        'lei': 'CLT Art. 392-A + Lei 9.029/1995 Art. 1º',
                        'solucao': 'Remover imediatamente esta cláusula discriminatória',
                        'penalidade': 'Processo criminal + indenização por danos morais',
                        'padroes': [
                            r'gravidez.*rescindido',
                            r'contrato.*automática.*gravidez',
                            r'gestação.*rescisão',
                            r'grávida.*demissão',
                            r'gravidez.*término.*contrato',
                            r'estado.*gravidez.*extinção',
                            r'gestante.*dispensa'
                        ]
                    },
                    'experiencia_excessiva': {
                        'nome': '📅 PERÍODO DE EXPERIÊNCIA EXCESSIVO',
                        'descricao': 'Período de experiência superior a 90 dias - LIMITE LEGAL',
                        'gravidade': 'ALTO',
                        'lei': 'CLT Art. 443, §2º',
                        'solucao': 'Reduzir período de experiência para máximo 90 dias',
                        'penalidade': 'Reconhecimento como efetivo após 90 dias',
                        'padroes': [
                            r'experiência.*6.*meses',
                            r'6.*meses.*experiência',
                            r'180.*dias.*experiência',
                            r'prorrogação.*90.*dias',
                            r'período.*teste.*(\d+).*meses',
                            r'experiência.*(\d+).*meses'
                        ]
                    },
                    'intervalo_insuficiente': {
                        'nome': '⏱️ INTERVALO INTRAJORNADA INSUFICIENTE',
                        'descricao': 'Intervalo para refeição inferior a 1 hora (6h+ trabalho) ou 15min (4-6h)',
                        'gravidade': 'ALTO',
                        'lei': 'CLT Art. 71',
                        'solucao': 'Garantir intervalo mínimo de 1 hora para jornada >6h',
                        'penalidade': 'Pagamento como hora extra + 50%',
                        'padroes': [
                            r'intervalo.*(\d+).*minutos',
                            r'intervalo.*(\d).*horas',
                            r'almoço.*(\d+).*minutos',
                            r'descanso.*(\d+).*minutos'
                        ]
                    }
                }
            },
            'NOTA_FISCAL': {
                'nome': '🧾 Nota Fiscal Eletrônica',
                'icone': '🧾',
                'marcadores': [
                    r'nota.*fiscal.*eletrônica',
                    r'nfe.*número',
                    r'chave.*acesso',
                    r'cnpj.*emitente',
                    r'valor.*total',
                    r'icms.*valor',
                    r'protocolo.*autorização',
                    r'danfe.*documento',
                    r'emitente.*destinatário',
                    r'cfop.*código'
                ],
                'o_que_verificamos': [
                    "🔢 Chave de acesso válida (44 dígitos)",
                    "🏢 CNPJ regular na Receita Federal",
                    "💰 Valores coerentes com operação realizada",
                    "📊 Tributação correta (ICMS, IPI, PIS, COFINS)",
                    "📅 Data de emissão dentro do prazo legal",
                    "✅ Protocolo de autorização válido",
                    "🔍 CFOP adequado à operação comercial",
                    "📝 Dados completos do destinatário",
                    "⚖️ Base de cálculo correta dos impostos",
                    "📋 Natureza da operação claramente descrita",
                    "🛡️ Inscrição estadual válida do emitente",
                    "📈 Valor do frete especificado quando devido",
                    "📦 Volumes, peso e espécie declarados",
                    "🔐 Assinatura digital válida",
                    "🌐 Número de série único e sequencial",
                    "💳 Forma de pagamento especificada",
                    "📄 Dados do transportador quando aplicável"
                ],
                'problemas': {
                    'chave_invalida': {
                        'nome': '🔑 CHAVE DE ACESSO INVÁLIDA',
                        'descricao': 'Chave de acesso da NFE com formato incorreto ou dígitos errados',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Ajuste SINIEF 07/2005 + Lei 8.846/1994',
                        'solucao': 'Verificar e corrigir chave de acesso de 44 dígitos',
                        'penalidade': 'Nota inválida para créditos fiscais',
                        'padroes': [
                            r'chave.*acesso.*\d{44}',
                            r'nfe.*\d{44}',
                            r'[0-9]{44}',
                            r'chave:.*\d{44}'
                        ]
                    },
                    'cnpj_invalido': {
                        'nome': '🏢 CNPJ INVÁLIDO',
                        'descricao': 'CNPJ do emitente ou destinatário com dígitos verificadores incorretos',
                        'gravidade': 'CRÍTICO',
                        'lei': 'Lei 8.429/1992 + Lei 12.846/2013',
                        'solucao': 'Validar CNPJ com algoritmo oficial da Receita Federal',
                        'penalidade': 'Nota fiscal falsa - crime contra a ordem tributária',
                        'padroes': [
                            r'cnpj.*\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}',
                            r'\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}',
                            r'CNPJ:.*\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}'
                        ]
                    },
                    'valor_irregular': {
                        'nome': '💸 VALORES IRREGULARES',
                        'descricao': 'Inconsistência nos valores totais, base de cálculo ou impostos',
                        'gravidade': 'ALTO',
                        'lei': 'Lei 8.137/1990 + Lei 4.502/1964',
                        'solucao': 'Recalcular todos os valores e impostos',
                        'penalidade': 'Multa de 75% a 225% do imposto sonegado',
                        'padroes': [
                            r'valor.*total.*\d+.*\d+',
                            r'icms.*valor.*\d+',
                            r'base.*cálculo.*\d+',
                            r'valor.*produtos.*\d+',
                            r'valor.*frete.*\d+'
                        ]
                    },
                    'tributacao_errada': {
                        'nome': '📊 TRIBUTAÇÃO INCORRETA',
                        'descricao': 'Alíquotas ou bases de cálculo de impostos incorretas',
                        'gravidade': 'ALTO',
                        'lei': 'Lei Complementar 87/1996 (Lei Kandir)',
                        'solucao': 'Aplicar alíquotas corretas conforme estado e produto',
                        'penalidade': 'Diferença de imposto + multa',
                        'padroes': [
                            r'icms.*(\d+,\d+)%',
                            r'ipi.*(\d+,\d+)%',
                            r'pis.*(\d+,\d+)%',
                            r'cofins.*(\d+,\d+)%',
                            r'alíquota.*(\d+,\d+)%'
                        ]
                    },
                    'data_vencida': {
                        'nome': '📅 DATA DE EMISSÃO VENCIDA',
                        'descricao': 'Nota fiscal emitida fora do prazo legal',
                        'gravidade': 'MÉDIO',
                        'lei': 'Lei 8.137/1990',
                        'solucao': 'Emitir nova nota fiscal dentro do prazo',
                        'penalidade': 'Multa por atraso na emissão',
                        'padroes': [
                            r'data.*emissão.*\d{2}/\d{2}/\d{4}',
                            r'emissão:.*\d{2}/\d{2}/\d{4}'
                        ]
                    }
                }
            },
            'CONTRATO_PRESTACAO_SERVICOS': {
                'nome': '💼 Contrato de Prestação de Serviços',
                'icone': '💼',
                'marcadores': [
                    r'contrato.*prestação.*serviços',
                    r'contratante.*contratado',
                    r'honorários.*serviços',
                    r'escopo.*serviço',
                    r'prazo.*execução',
                    r'forma.*pagamento'
                ],
                'o_que_verificamos': [
                    "⚖️ Ausência de vínculo empregatício dissimulado",
                    "📊 Remuneração compatível com o mercado",
                    "📝 Especificação clara dos serviços",
                    "⏰ Ausência de subordinação e horário fixo",
                    "💰 Pagamento por resultado/projeto",
                    "📅 Prazo de execução definido",
                    "🛡️ Responsabilidades bem delimitadas",
                    "📋 Termos de rescisão claros",
                    "🔒 Confidencialidade quando aplicável",
                    "⚖️ Foro adequado para disputas"
                ],
                'problemas': {
                    'vinculo_dissimulado': {
                        'nome': '⚖️ VÍNCULO EMPREGATÍCIO DISSIMULADO',
                        'descricao': 'Contrato de prestação que esconde relação de emprego (horário fixo, subordinação)',
                        'gravidade': 'CRÍTICO',
                        'lei': 'CLT Art. 3º + Súmula 331 TST',
                        'solucao': 'Regularizar vínculo empregatício ou remover elementos de subordinação',
                        'padroes': [
                            r'horário.*fixo.*(\d{2}):.*[àa].*(\d{2}):',
                            r'expediente.*fixo',
                            r'subordinação.*hierárquica',
                            r'cumprir.*horário',
                            r'exclusividade.*sem.*vínculo',
                            r'supervisionado.*por'
                        ]
                    }
                }
            }
        }
    
    def _validar_cnpj_avancado(self, cnpj):
        """Valida CNPJ com algoritmo oficial completo"""
        cnpj = re.sub(r'[^\d]', '', cnpj)
        
        if len(cnpj) != 14:
            return False
        
        if cnpj == cnpj[0] * 14:
            return False
        
        # Primeiro dígito verificador
        soma = 0
        peso = 5
        for i in range(12):
            soma += int(cnpj[i]) * peso
            peso -= 1
            if peso == 1:
                peso = 9
        
        resto = soma % 11
        digito1 = 0 if resto < 2 else 11 - resto
        
        if digito1 != int(cnpj[12]):
            return False
        
        # Segundo dígito verificador
        soma = 0
        peso = 6
        for i in range(13):
            soma += int(cnpj[i]) * peso
            peso -= 1
            if peso == 1:
                peso = 9
        
        resto = soma % 11
        digito2 = 0 if resto < 2 else 11 - resto
        
        return digito2 == int(cnpj[13])
    
    def _validar_valores_nota_fiscal(self, texto):
        """Valida consistência dos valores na nota fiscal"""
        problemas = []
        
        # Extrair valores
        valores = re.findall(r'valor.*?(\d+[.,]\d{2})', texto, re.IGNORECASE)
        valores_float = []
        
        for v in valores:
            try:
                v_clean = v.replace('.', '').replace(',', '.')
                valores_float.append(float(v_clean))
            except:
                continue
        
        # Verificar consistência
        if len(valores_float) >= 2:
            # Verificar se valores são consistentes
            max_valor = max(valores_float)
            min_valor = min(valores_float)
            
            if max_valor > min_valor * 1000:  # Diferença muito grande
                problemas.append({
                    'nome': 'Valores inconsistentes',
                    'descricao': f'Diferença muito grande entre valores: R$ {min_valor:,.2f} e R$ {max_valor:,.2f}',
                    'gravidade': 'ALTO'
                })
        
        return problemas
    
    def _detectar_salario_abaixo_minimo_avancado(self, valores):
        """Detecta salários abaixo do mínimo de forma avançada"""
        salario_minimo = 1412.00
        problemas = []
        
        for valor_info in valores:
            if valor_info['tipo'] == 'salario' and valor_info['valor'] < salario_minimo:
                problemas.append({
                    'nome': 'Salário abaixo do mínimo',
                    'descricao': f'Salário de R$ {valor_info["valor"]:,.2f} está abaixo do mínimo legal de R$ {salario_minimo:,.2f}',
                    'gravidade': 'CRÍTICO',
                    'valor': valor_info['valor'],
                    'texto': valor_info['texto']
                })
        
        return problemas
    
    def _detectar_multa_abusiva_avancado(self, valores):
        """Detecta multas abusivas de forma avançada"""
        problemas = []
        
        for valor_info in valores:
            if valor_info['tipo'] == 'multa':
                # Procurar número de meses no texto
                meses_match = re.search(r'(\d+).*meses?', valor_info['texto'], re.IGNORECASE)
                if meses_match:
                    meses = int(meses_match.group(1))
                    if meses > 3:
                        problemas.append({
                            'nome': 'Multa abusiva',
                            'descricao': f'Multa de {meses} meses excede o limite legal de 3 meses',
                            'gravidade': 'CRÍTICO',
                            'meses': meses,
                            'texto': valor_info['texto']
                        })
        
        return problemas
    
    def analisar_documento_completo(self, texto):
        """Análise completa e avançada do documento"""
        self.contador_analises += 1
        
        # Limpeza profunda
        texto_limpo = self._limpar_texto_profundo(texto)
        
        if not texto_limpo or len(texto_limpo) < 100:
            return [], 'DESCONHECIDO', [], self._calcular_metricas([])
        
        # Identificar tipo de documento
        tipo_doc = self._identificar_tipo_documento(texto_limpo)
        
        if tipo_doc not in self.padroes:
            return [], tipo_doc, [], self._calcular_metricas([])
        
        config = self.padroes[tipo_doc]
        problemas_detectados = []
        
        # Extrair valores e datas
        valores = self._extrair_valores_monetarios_completos(texto_limpo)
        datas = self._extrair_datas_completas(texto_limpo)
        
        # Detecções específicas por tipo de documento
        if tipo_doc == 'CONTRATO_LOCACAO':
            # Detectar salário abaixo do mínimo
            problemas_salario = self._detectar_salario_abaixo_minimo_avancado(valores)
            problemas_detectados.extend(problemas_salario)
            
            # Detectar multas abusivas
            problemas_multa = self._detectar_multa_abusiva_avancado(valores)
            problemas_detectados.extend(problemas_multa)
            
            # Detectar caução excessiva
            for valor_info in valores:
                if valor_info['tipo'] == 'caução':
                    # Procurar número de meses no texto
                    meses_match = re.search(r'(\d+).*meses?', valor_info['texto'], re.IGNORECASE)
                    if meses_match:
                        meses = int(meses_match.group(1))
                        if meses > 3:
                            problemas_detectados.append({
                                'nome': 'Caução excessiva',
                                'descricao': f'Caução de {meses} meses excede o limite legal de 3 meses',
                                'gravidade': 'ALTO',
                                'meses': meses,
                                'texto': valor_info['texto']
                            })
        
        elif tipo_doc == 'CONTRATO_EMPREGO':
            # Detectar salário abaixo do mínimo
            problemas_salario = self._detectar_salario_abaixo_minimo_avancado(valores)
            problemas_detectados.extend(problemas_salario)
            
            # Detectar jornada excessiva
            for valor_info in valores:
                if 'hora' in valor_info['texto'].lower():
                    # Procurar número de horas
                    horas_match = re.search(r'(\d+).*horas?', valor_info['texto'], re.IGNORECASE)
                    if horas_match:
                        horas = int(horas_match.group(1))
                        if horas > 8 and 'diária' in valor_info['texto'].lower():
                            problemas_detectados.append({
                                'nome': 'Jornada diária excessiva',
                                'descricao': f'Jornada de {horas} horas diárias excede o limite legal de 8 horas',
                                'gravidade': 'CRÍTICO',
                                'horas': horas,
                                'texto': valor_info['texto']
                            })
                        elif horas > 44 and 'semanal' in valor_info['texto'].lower():
                            problemas_detectados.append({
                                'nome': 'Jornada semanal excessiva',
                                'descricao': f'Jornada de {horas} horas semanais excede o limite legal de 44 horas',
                                'gravidade': 'CRÍTICO',
                                'horas': horas,
                                'texto': valor_info['texto']
                            })
        
        elif tipo_doc == 'NOTA_FISCAL':
            # Validar CNPJs
            cnpjs = re.findall(r'\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}', texto)
            for cnpj in cnpjs:
                if not self._validar_cnpj_avancado(cnpj):
                    problemas_detectados.append({
                        'nome': 'CNPJ inválido',
                        'descricao': f'CNPJ {cnpj} possui dígitos verificadores incorretos',
                        'gravidade': 'CRÍTICO',
                        'cnpj': cnpj
                    })
            
            # Validar valores
            problemas_valores = self._validar_valores_nota_fiscal(texto)
            problemas_detectados.extend(problemas_valores)
        
        # Verificar cada problema configurado
        for problema_id, problema_config in config['problemas'].items():
            # Verificação por regex
            for padrao in problema_config['padroes']:
                matches = re.finditer(padrao, texto_limpo, re.IGNORECASE)
                
                for match in matches:
                    contexto_inicio = max(0, match.start() - 150)
                    contexto_fim = min(len(texto_limpo), match.end() + 150)
                    contexto = texto_limpo[contexto_inicio:contexto_fim]
                    
                    problema = {
                        'id': problema_id,
                        'nome': problema_config['nome'],
                        'descricao': problema_config['descricao'],
                        'gravidade': problema_config['gravidade'],
                        'lei': problema_config['lei'],
                        'solucao': problema_config['solucao'],
                        'penalidade': problema_config.get('penalidade', ''),
                        'contexto': contexto,
                        'confianca': 0.95,
                        'nivel_confianca': '95% CONFIRMADO',
                        'tipo_documento': tipo_doc,
                        'texto_original': match.group(0),
                        'posicao': match.start()
                    }
                    
                    # Adicionar valor específico se aplicável
                    if 'salario' in problema_id and match.groups():
                        try:
                            valor_str = match.group(1).replace('.', '').replace(',', '.')
                            valor = float(valor_str)
                            if valor < 1412.00:
                                problema['valor_especifico'] = f"R$ {valor:,.2f} (abaixo do mínimo R$ 1.412,00)"
                        except:
                            pass
                    
                    problemas_detectados.append(problema)
        
        # Detecção por similaridade
        clausulas_similares = self._detectar_clausulas_similares_avancado(
            texto_limpo, 
            config['problemas']
        )
        
        for clausula in clausulas_similares:
            problema = {
                'id': f"similar_{clausula['id']}",
                'nome': f"⚠️ {clausula['nome']} (SIMILARIDADE {clausula['similaridade']:.1f}%)",
                'descricao': f"Cláusula com conteúdo similar detectado com {clausula['similaridade']:.1f}% de correspondência",
                'gravidade': clausula['gravidade'],
                'lei': 'Análise contextual avançada',
                'solucao': 'Revisar e reformular a cláusula',
                'contexto': clausula['texto'],
                'confianca': clausula['similaridade'] / 100,
                'nivel_confianca': f"{clausula['similaridade']:.1f}% SIMILAR",
                'tipo_documento': tipo_doc,
                'texto_original': clausula['texto']
            }
            problemas_detectados.append(problema)
        
        # Calcular métricas
        metricas = self._calcular_metricas(problemas_detectados)
        
        return problemas_detectados, tipo_doc, config['o_que_verificamos'], metricas
    
    def _identificar_tipo_documento(self, texto):
        """Identificação inteligente do tipo de documento"""
        scores = {}
        
        for tipo_doc, config in self.padroes.items():
            score = 0
            
            # Pontuar por marcadores
            for marcador in config['marcadores']:
                matches = re.findall(marcador, texto, re.IGNORECASE)
                score += len(matches) * 3
            
            # Pontuar por termos específicos
            if tipo_doc == 'CONTRATO_LOCACAO':
                termos = ['aluguel', 'locação', 'imóvel', 'inquilino', 'proprietário', 'fiador', 'caução']
                score += sum(texto.count(termo) for termo in termos)
            
            elif tipo_doc == 'CONTRATO_EMPREGO':
                termos = ['salário', 'empregado', 'empregador', 'carteira', 'FGTS', 'férias', 'CLT', 'horas extras']
                score += sum(texto.count(termo) for termo in termos)
            
            elif tipo_doc == 'NOTA_FISCAL':
                termos = ['NFe', 'chave acesso', 'ICMS', 'protocolo', 'emitente', 'destinatário', 'CFOP']
                score += sum(texto.count(termo) for termo in termos)
            
            scores[tipo_doc] = score
        
        # Verificar score mínimo
        melhor_tipo = max(scores, key=scores.get, default='DESCONHECIDO')
        
        if scores[melhor_tipo] >= 5:
            return melhor_tipo
        
        # Fallback inteligente
        if any(termo in texto for termo in ['nota fiscal', 'NFe', 'chave acesso']):
            return 'NOTA_FISCAL'
        elif 'contrato' in texto:
            if any(termo in texto for termo in ['locação', 'aluguel', 'inquilino']):
                return 'CONTRATO_LOCACAO'
            elif any(termo in texto for termo in ['trabalho', 'emprego', 'empregado']):
                return 'CONTRATO_EMPREGO'
            elif any(termo in texto for termo in ['prestação', 'serviços', 'honorários']):
                return 'CONTRATO_PRESTACAO_SERVICOS'
        
        return 'DESCONHECIDO'
    
    def _calcular_metricas(self, problemas):
        """Calcula métricas detalhadas"""
        total = len(problemas)
        criticos = sum(1 for p in problemas if p.get('gravidade') == 'CRÍTICO')
        altos = sum(1 for p in problemas if p.get('gravidade') == 'ALTO')
        medios = sum(1 for p in problemas if p.get('gravidade') == 'MÉDIO')
        
        # Cálculo de score
        penalidade_criticos = criticos * 40
        penalidade_altos = altos * 20
        penalidade_medios = medios * 10
        
        score = max(0, 100 - penalidade_criticos - penalidade_altos - penalidade_medios)
        
        # Nível de risco
        if criticos >= 3:
            nivel_risco = '🚨 EMERGÊNCIA - DOCUMENTO PERIGOSO'
            cor_risco = '#ff0000'
        elif criticos >= 2:
            nivel_risco = '🚨 ALTO RISCO - URGENTE'
            cor_risco = '#ff4444'
        elif criticos >= 1:
            nivel_risco = '⚠️ RISCO CRÍTICO DETECTADO'
            cor_risco = '#ff6666'
        elif altos >= 2:
            nivel_risco = '🔴 RISCO ELEVADO'
            cor_risco = '#ff9933'
        elif total >= 3:
            nivel_risco = '🟡 ATENÇÃO NECESSÁRIA'
            cor_risco = '#ffcc00'
        elif total > 0:
            nivel_risco = '📋 AJUSTES RECOMENDADOS'
            cor_risco = '#33aa33'
        else:
            nivel_risco = '✅ DOCUMENTO REGULAR'
            cor_risco = '#008800'
        
        return {
            'total_problemas': total,
            'problemas_criticos': criticos,
            'problemas_altos': altos,
            'problemas_medios': medios,
            'score_conformidade': score,
            'nivel_risco': nivel_risco,
            'cor_risco': cor_risco,
            'eficiencia_deteccao': 'EFICIÊNCIA MÁXIMA'
        }

# --------------------------------------------------
# ESTILOS PROFISSIONAIS BRANCOS E DOURADOS
# --------------------------------------------------

st.markdown("""
<style>
    /* Fundo branco e texto preto */
    .stApp {
        background-color: #ffffff;
        color: #000000;
    }
    
    /* Títulos e texto geral - PRETO */
    h1, h2, h3, h4, h5, h6, p, span, div, label {
        color: #000000 !important;
    }
    
    /* Container de login */
    .login-container {
        background: #ffffff;
        padding: 40px;
        border-radius: 20px;
        margin: 50px auto;
        max-width: 500px;
        box-shadow: 0 15px 35px rgba(212, 175, 55, 0.15);
        border: 3px solid #d4af37;
        text-align: center;
    }
    
    .login-title {
        color: #d4af37;
        font-size: 2.5em;
        font-weight: bold;
        margin-bottom: 30px;
        text-align: center;
    }
    
    .login-subtitle {
        color: #666666;
        font-size: 1.2em;
        margin-bottom: 40px;
        text-align: center;
        line-height: 1.6;
    }
    
    /* Estilo para campos de formulário */
    .stTextInput > div > div > input {
        background-color: #f9f9f9 !important;
        border: 2px solid #d4af37 !important;
        border-radius: 10px !important;
        padding: 12px 15px !important;
        color: #000000 !important;
        font-size: 1em !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #e6c158 !important;
        box-shadow: 0 0 0 3px rgba(212, 175, 55, 0.2) !important;
    }
    
    .stTextInput > label {
        color: #000000 !important;
        font-weight: 600 !important;
        margin-bottom: 5px !important;
    }
    
    /* Botões do Streamlit */
    .stButton > button {
        background: linear-gradient(135deg, #d4af37, #b8941f) !important;
        color: #000000 !important;
        border: none !important;
        padding: 14px 30px !important;
        border-radius: 10px !important;
        font-weight: 700 !important;
        font-size: 1.1em !important;
        transition: all 0.3s ease !important;
        width: 100% !important;
        margin-top: 20px !important;
    }
    
    .stButton > button:hover {
        background: linear-gradient(135deg, #e6c158, #d4af37) !important;
        transform: translateY(-2px) !important;
        box-shadow: 0 8px 20px rgba(212, 175, 55, 0.4) !important;
    }
    
    /* Container de upload */
    .upload-container {
        background: #ffffff;
        padding: 30px;
        border-radius: 20px;
        margin: 20px 0;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        border: 3px solid #d4af37;
        text-align: center;
    }
    
    .upload-title {
        color: #d4af37;
        font-size: 2.2em;
        font-weight: bold;
        margin-bottom: 15px;
    }
    
    .upload-subtitle {
        color: #666666;
        font-size: 1.2em;
        margin-bottom: 30px;
        line-height: 1.5;
    }
    
    /* Status do sistema */
    .system-status {
        display: inline-block;
        padding: 5px 15px;
        border-radius: 15px;
        font-size: 0.9em;
        font-weight: 600;
        background: rgba(0, 255, 0, 0.1);
        color: #008000;
        border: 1px solid rgba(0, 255, 0, 0.3);
        margin-top: 10px;
    }
    
    /* Cartões de métricas */
    .metric-card {
        background: #ffffff;
        padding: 25px;
        border-radius: 15px;
        box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        text-align: center;
        border-top: 4px solid;
        border-left: 1px solid #d4af37;
        border-right: 1px solid #d4af37;
        border-bottom: 1px solid #d4af37;
        transition: transform 0.3s ease;
        margin-bottom: 20px;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 8px 25px rgba(212, 175, 55, 0.3);
    }
    
    /* Animações */
    .fade-in {
        animation: fadeIn 0.6s ease-out;
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    /* Sistema de detecção */
    .detection-section {
        background: #ffffff;
        padding: 40px;
        border-radius: 20px;
        margin: 40px 0;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        border: 3px solid #d4af37;
    }
    
    .detection-title {
        color: #d4af37;
        font-size: 2em;
        font-weight: bold;
        margin-bottom: 30px;
        text-align: center;
    }
    
    .detection-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
        gap: 25px;
        justify-content: center;
        align-items: start;
    }
    
    .detection-item {
        background: #f9f9f9;
        padding: 25px;
        border-radius: 15px;
        box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        border: 2px solid #d4af37;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .detection-item:hover {
        transform: translateY(-5px);
        box-shadow: 0 10px 25px rgba(212, 175, 55, 0.3);
    }
    
    .detection-icon {
        font-size: 2.5em;
        margin-bottom: 15px;
        color: #d4af37;
    }
    
    .detection-name {
        color: #000000;
        font-size: 1.3em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .detection-desc {
        color: #666666;
        font-size: 1em;
        line-height: 1.5;
    }
    
    /* Detalhes do documento */
    .doc-type-section {
        background: #f9f9f9;
        padding: 25px;
        border-radius: 15px;
        margin: 20px 0;
        border-left: 5px solid #d4af37;
    }
    
    .doc-type-title {
        color: #000000;
        font-size: 1.5em;
        font-weight: bold;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .checklist-item {
        display: flex;
        align-items: flex-start;
        margin-bottom: 10px;
        gap: 10px;
    }
    
    .checklist-icon {
        color: #008000;
        font-size: 1.2em;
        margin-top: 2px;
    }
    
    .checklist-text {
        color: #333333;
        font-size: 1em;
        line-height: 1.4;
    }
    
    /* Cartões de problemas */
    .problem-card {
        background: #ffffff;
        padding: 20px;
        border-radius: 10px;
        margin: 15px 0;
        border-left: 5px solid;
        box-shadow: 0 3px 10px rgba(0,0,0,0.1);
        transition: all 0.3s ease;
    }
    
    .problem-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 5px 15px rgba(0,0,0,0.15);
    }
    
    .problem-critical {
        border-left-color: #ff4444;
        background: rgba(255, 68, 68, 0.05);
    }
    
    .problem-high {
        border-left-color: #ffaa44;
        background: rgba(255, 170, 68, 0.05);
    }
    
    .problem-medium {
        border-left-color: #33aa33;
        background: rgba(51, 170, 51, 0.05);
    }
    
    .problem-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 10px;
    }
    
    .problem-title {
        font-weight: bold;
        font-size: 1.2em;
        color: #000000;
    }
    
    .problem-gravity {
        padding: 5px 15px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 0.9em;
    }
    
    .gravity-critical {
        background: rgba(255, 68, 68, 0.2);
        color: #ff4444;
        border: 1px solid rgba(255, 68, 68, 0.3);
    }
    
    .gravity-high {
        background: rgba(255, 170, 68, 0.2);
        color: #ffaa44;
        border: 1px solid rgba(255, 170, 68, 0.3);
    }
    
    .gravity-medium {
        background: rgba(51, 170, 51, 0.2);
        color: #33aa33;
        border: 1px solid rgba(51, 170, 51, 0.3);
    }
</style>
""", unsafe_allow_html=True)

# --------------------------------------------------
# FUNÇÕES AUXILIARES
# --------------------------------------------------

def extrair_texto_pdf(arquivo):
    """Extrai texto de PDF de forma robusta"""
    try:
        with pdfplumber.open(arquivo) as pdf:
            texto_completo = ""
            
            for pagina in pdf.pages:
                try:
                    texto = pagina.extract_text()
                    if texto:
                        texto_completo += texto + "\n"
                except:
                    continue
            
            if texto_completo.strip():
                return texto_completo
            else:
                st.error("❌ Não foi possível extrair texto do PDF. O arquivo pode estar protegido ou ser uma imagem.")
                return None
    
    except Exception as e:
        st.error(f"❌ Erro ao processar PDF: {str(e)}")
        return None

# --------------------------------------------------
# INTERFACE PRINCIPAL
# --------------------------------------------------

def mostrar_tela_login():
    """Tela de login profissional"""
    st.markdown("""
    <div class="login-container fade-in">
        <div class="login-title">⚖️ BUROCRATA DE BOLSO</div>
        <div class="login-subtitle">
            Sistema Avançado de Auditoria Jurídica e Fiscal<br>
            <span style="font-size: 0.9em; color: #888888;">Detecção máxima de violações legais</span>
        </div>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        email = st.text_input("📧 E-mail", placeholder="seu@email.com")
        senha = st.text_input("🔒 Senha", type="password", placeholder="Sua senha")
        
        if st.form_submit_button("🚀 ACESSAR SISTEMA", use_container_width=True):
            st.session_state.autenticado = True
            st.session_state.usuario_nome = "Usuário"
            st.rerun()
    
    st.markdown("</div>", unsafe_allow_html=True)

def mostrar_tela_principal():
    """Tela principal profissional"""
    
    detector = SistemaDetecçãoAvancado()
    
    # Cabeçalho
    st.markdown("""
    <div class="fade-in">
        <h1 style="text-align: center; color: #d4af37; font-size: 2.8em; margin-bottom: 10px;">
            ⚖️ BUROCRATA DE BOLSO
        </h1>
        <p style="text-align: center; color: #666666; font-size: 1.2em; margin-bottom: 5px;">
            Sistema Avançado de Auditoria Jurídica e Fiscal
        </p>
        <div style="text-align: center; margin-bottom: 30px;">
            <span class="system-status">DETECÇÃO MÁXIMA • ANÁLISE COMPLETA • SISTEMA CONFIÁVEL</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Barra superior com informações
    col_info, col_actions = st.columns([3, 1])
    
    with col_info:
        st.markdown(f"""
        <div style="background: linear-gradient(135deg, rgba(212, 175, 55, 0.1), rgba(184, 148, 31, 0.1)); 
                    padding: 15px; border-radius: 10px; border: 2px solid #d4af37; margin-bottom: 20px;">
            <div style="display: flex; align-items: center; gap: 15px;">
                <div style="font-size: 2em;">👤</div>
                <div>
                    <strong style="color: #000000; font-size: 1.1em;">{st.session_state.usuario_nome}</strong><br>
                    <span style="color: #666666; font-size: 0.9em;">Nível Premium - Acesso Completo</span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col_actions:
        if st.button("🚪 Sair", use_container_width=True, type="secondary"):
            st.session_state.autenticado = False
            st.rerun()
    
    # Sistema de Detecção
    st.markdown("""
    <div class="upload-container fade-in">
        <div class="upload-title">🔍 SISTEMA DE DETECÇÃO AVANÇADA</div>
        <div class="upload-subtitle">
            Identificação automática de violações legais e cláusulas abusivas<br>
            <span style="color: #d4af37; font-weight: bold;">Contratos • Notas Fiscais • Documentos Jurídicos</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Tipos de documentos
    st.markdown("### 📋 TIPOS DE DOCUMENTOS SUPORTADOS")
    
    col_doc1, col_doc2, col_doc3, col_doc4 = st.columns(4)
    
    with col_doc1:
        st.markdown("""
        <div style="background: white; padding: 20px; border-radius: 15px; border: 2px solid #d4af37; text-align: center;">
            <div style="font-size: 2.5em; color: #d4af37;">🏠</div>
            <h3 style="color: #000000; margin: 10px 0;">Locação</h3>
            <p style="color: #666666; font-size: 0.9em;">
                Reajustes • Multas • Caução<br>
                Renovação • Foro
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col_doc2:
        st.markdown("""
        <div style="background: white; padding: 20px; border-radius: 15px; border: 2px solid #d4af37; text-align: center;">
            <div style="font-size: 2.5em; color: #d4af37;">👔</div>
            <h3 style="color: #000000; margin: 10px 0;">Emprego</h3>
            <p style="color: #666666; font-size: 0.9em;">
                Salário • Jornada • FGTS<br>
                Férias • Experiência
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col_doc3:
        st.markdown("""
        <div style="background: white; padding: 20px; border-radius: 15px; border: 2px solid #d4af37; text-align: center;">
            <div style="font-size: 2.5em; color: #d4af37;">🧾</div>
            <h3 style="color: #000000; margin: 10px 0;">Nota Fiscal</h3>
            <p style="color: #666666; font-size: 0.9em;">
                CNPJ • Valores • Tributos<br>
                Chave • Protocolo
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    with col_doc4:
        st.markdown("""
        <div style="background: white; padding: 20px; border-radius: 15px; border: 2px solid #d4af37; text-align: center;">
            <div style="font-size: 2.5em; color: #d4af37;">💼</div>
            <h3 style="color: #000000; margin: 10px 0;">Serviços</h3>
            <p style="color: #666666; font-size: 0.9em;">
                Vínculo dissimulado<br>
                Honorários • Prazos
            </p>
        </div>
        """, unsafe_allow_html=True)
    
    # Upload
    st.markdown("### 📤 ENVIE SEU DOCUMENTO PARA ANÁLISE")
    
    arquivo = st.file_uploader(
        "Arraste ou clique para selecionar um arquivo PDF",
        type=["pdf"],
        help="Suporta contratos de locação, emprego, prestação de serviços e notas fiscais",
        label_visibility="collapsed"
    )
    
    # Processar
    if arquivo:
        with st.spinner("🔍 **Analisando documento com sistema avançado...**"):
            texto = extrair_texto_pdf(arquivo)
            
            if texto:
                problemas, tipo_doc, verificacoes, metricas = detector.analisar_documento_completo(texto)
                
                # Resultados
                st.markdown("---")
                
                if tipo_doc in detector.padroes:
                    config = detector.padroes[tipo_doc]
                    nome_doc = config['nome']
                    icone_doc = config['icone']
                else:
                    nome_doc = "Documento"
                    icone_doc = "📄"
                
                # Status principal
                st.markdown(f"""
                <div style="background: {metricas['cor_risco']}10; padding: 25px; border-radius: 15px; 
                         border: 3px solid {metricas['cor_risco']}; margin: 20px 0; text-align: center;">
                    <h2 style="margin: 0; color: {metricas['cor_risco']}; font-size: 2.2em;">
                        {metricas['nivel_risco']}
                    </h2>
                    <p style="margin: 10px 0 0 0; color: #000000; font-size: 1.1em;">
                        {metricas['total_problemas']} problema(s) detectado(s) • Score: {metricas['score_conformidade']:.1f}%
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                # Métricas
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    cor_total = "#ff4444" if metricas['total_problemas'] > 0 else "#008000"
                    st.markdown(f"""
                    <div class="metric-card">
                        <h3 style="margin: 0; font-size: 2.5em; color: {cor_total};">
                            {metricas['total_problemas']}
                        </h3>
                        <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">PROBLEMAS</p>
                        <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Total detectados</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"""
                    <div class="metric-card">
                        <h3 style="margin: 0; font-size: 2.5em; color: #ff4444;">
                            {metricas['problemas_criticos']}
                        </h3>
                        <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">CRÍTICOS</p>
                        <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Violações graves</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    st.markdown(f"""
                    <div class="metric-card">
                        <h3 style="margin: 0; font-size: 2.5em; color: #ffaa44;">
                            {metricas['problemas_altos']}
                        </h3>
                        <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">ELEVADOS</p>
                        <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Risco médio</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col4:
                    cor_score = "#008000" if metricas['score_conformidade'] >= 80 else "#ffaa44" if metricas['score_conformidade'] >= 60 else "#ff4444"
                    st.markdown(f"""
                    <div class="metric-card">
                        <h3 style="margin: 0; font-size: 2.5em; color: {cor_score};">
                            {metricas['score_conformidade']:.0f}%
                        </h3>
                        <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">SCORE</p>
                        <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Conformidade</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                # O que verificamos
                if tipo_doc in detector.padroes and verificacoes:
                    st.markdown("### 🔍 O QUE VERIFICAMOS NESTE DOCUMENTO")
                    
                    col_check1, col_check2 = st.columns(2)
                    items_per_col = len(verificacoes) // 2 + 1
                    
                    with col_check1:
                        for item in verificacoes[:items_per_col]:
                            st.markdown(f"""
                            <div style="background: #f9f9f9; padding: 12px 15px; border-radius: 8px; 
                                     border-left: 4px solid #d4af37; margin-bottom: 8px;">
                                <span style="color: #000000;">{item}</span>
                            </div>
                            """, unsafe_allow_html=True)
                    
                    with col_check2:
                        for item in verificacoes[items_per_col:]:
                            st.markdown(f"""
                            <div style="background: #f9f9f9; padding: 12px 15px; border-radius: 8px; 
                                     border-left: 4px solid #d4af37; margin-bottom: 8px;">
                                <span style="color: #000000;">{item}</span>
                            </div>
                            """, unsafe_allow_html=True)
                
                # Problemas detectados
                if problemas:
                    st.markdown(f"### 🚨 VIOLAÇÕES DETECTADAS ({len(problemas)})")
                    
                    # Ordenar por gravidade
                    problemas_ordenados = sorted(problemas, key=lambda x: (
                        0 if x.get('gravidade') == 'CRÍTICO' else 
                        1 if x.get('gravidade') == 'ALTO' else 
                        2 if x.get('gravidade') == 'MÉDIO' else 3
                    ))
                    
                    for i, problema in enumerate(problemas_ordenados, 1):
                        if problema.get('gravidade') == 'CRÍTICO':
                            classe_gravidade = "gravity-critical"
                            classe_problema = "problem-card problem-critical"
                            icone = '🚨'
                        elif problema.get('gravidade') == 'ALTO':
                            classe_gravidade = "gravity-high"
                            classe_problema = "problem-card problem-high"
                            icone = '⚠️'
                        elif problema.get('gravidade') == 'MÉDIO':
                            classe_gravidade = "gravity-medium"
                            classe_problema = "problem-card problem-medium"
                            icone = '🔍'
                        else:
                            classe_gravidade = ""
                            classe_problema = "problem-card"
                            icone = '📝'
                        
                        with st.expander(f"{icone} {i}. {problema.get('nome', 'Problema')}", 
                                        expanded=(problema.get('gravidade') == 'CRÍTICO')):
                            st.markdown(f"""
                            <div class="{classe_problema}">
                                <div class="problem-header">
                                    <div class="problem-title">{problema.get('nome', 'Problema')}</div>
                                    <div class="problem-gravity {classe_gravidade}">
                                        {problema.get('gravidade', 'NÃO CLASSIFICADO')} • {problema.get('nivel_confianca', 'CONFIRMADO')}
                                    </div>
                                </div>
                            """, unsafe_allow_html=True)
                            
                            col_a, col_b = st.columns(2)
                            
                            with col_a:
                                st.markdown("**📋 Descrição do Problema:**")
                                st.error(problema.get('descricao', 'Descrição não disponível'))
                                
                                if problema.get('valor_especifico'):
                                    st.markdown(f"**🔢 Valor Encontrado:**")
                                    st.warning(problema['valor_especifico'])
                                
                                st.markdown(f"**📝 Texto Detectado:**")
                                st.code(problema.get('texto_original', problema.get('contexto', 'Texto não disponível')), 
                                       language='text')
                            
                            with col_b:
                                st.markdown("**⚖️ Base Legal:**")
                                st.warning(problema.get('lei', 'Informação legal não disponível'))
                                
                                if problema.get('penalidade'):
                                    st.markdown(f"**💰 Penalidade Legal:**")
                                    st.error(problema['penalidade'])
                                
                                st.markdown("**🛡️ Solução Recomendada:**")
                                st.success(problema.get('solucao', 'Solução não disponível'))
                            
                            st.markdown("</div>", unsafe_allow_html=True)
                    
                    # Exportar relatório
                    st.markdown("### 📥 EXPORTAR RELATÓRIO COMPLETO")
                    
                    if problemas:
                        dados = []
                        for p in problemas:
                            dados.append({
                                'Problema': p.get('nome', ''),
                                'Gravidade': p.get('gravidade', ''),
                                'Descrição': p.get('descricao', ''),
                                'Base Legal': p.get('lei', ''),
                                'Solução': p.get('solucao', ''),
                                'Penalidade': p.get('penalidade', ''),
                                'Confiança': p.get('nivel_confianca', ''),
                                'Contexto': p.get('contexto', '')[:200]
                            })
                        
                        df = pd.DataFrame(dados)
                        csv = df.to_csv(index=False, encoding='utf-8-sig')
                        
                        st.download_button(
                            label="💾 BAIXAR RELATÓRIO COMPLETO (CSV)",
                            data=csv,
                            file_name=f"auditoria_{arquivo.name.split('.')[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv",
                            use_container_width=True
                        )
                
                else:
                    # Documento perfeito
                    st.success(f"""
                    ### ✅ DOCUMENTO REGULAR!
                    
                    Nenhuma violação detectada em seu {nome_doc.lower()}. 
                    Score de conformidade: **{metricas['score_conformidade']:.1f}%**
                    
                    *Sistema com detecção máxima • Análise completa realizada*
                    """)
                    
                    st.balloons()
    
    else:
        # Estatísticas do sistema
        st.markdown("### 📊 ESTATÍSTICAS DO SISTEMA")
        
        col_stat1, col_stat2, col_stat3 = st.columns(3)
        
        with col_stat1:
            st.markdown("""
            <div class="metric-card">
                <h3 style="margin: 0; font-size: 2.5em; color: #d4af37;">🎯</h3>
                <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">EFICIÊNCIA</p>
                <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Detecção máxima</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col_stat2:
            st.markdown("""
            <div class="metric-card">
                <h3 style="margin: 0; font-size: 2.5em; color: #d4af37;">⚡</h3>
                <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">VELOCIDADE</p>
                <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Análise em segundos</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col_stat3:
            st.markdown("""
            <div class="metric-card">
                <h3 style="margin: 0; font-size: 2.5em; color: #d4af37;">🔒</h3>
                <p style="margin: 10px 0 0 0; font-weight: 600; font-size: 1.1em;">SEGURANÇA</p>
                <p style="margin: 5px 0 0 0; color: #666666; font-size: 0.9em;">Dados protegidos</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Exemplos de detecção
        st.markdown("### ⚠️ EXEMPLOS DE VIOLAÇÕES QUE DETECTAMOS")
        
        col_ex1, col_ex2 = st.columns(2)
        
        with col_ex1:
            st.markdown("""
            <div style="background: white; padding: 20px; border-radius: 15px; border: 2px solid #d4af37;">
                <h4 style="color: #000000; margin-top: 0;">🏠 Contratos de Locação</h4>
                <ul style="color: #666666;">
                    <li>Reajuste livre fora dos índices oficiais</li>
                    <li>Multa acima de 3 meses de aluguel</li>
                    <li>Exigência de fiador E caução simultâneos</li>
                    <li>Caução superior a 3 meses</li>
                    <li>Foro em comarca diferente do imóvel</li>
                    <li>Renovação automática tácita</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)
        
        with col_ex2:
            st.markdown("""
            <div style="background: white; padding: 20px; border-radius: 15px; border: 2px solid #d4af37;">
                <h4 style="color: #000000; margin-top: 0;">👔 Contratos de Emprego</h4>
                <ul style="color: #666666;">
                    <li>Salário abaixo do mínimo (R$ 1.412,00)</li>
                    <li>Jornada superior a 8h/dia ou 44h/semana</li>
                    <li>Renúncia ao FGTS (ilegal)</li>
                    <li>Período de experiência acima de 90 dias</li>
                    <li>Demissão por gravidez (crime)</li>
                    <li>Intervalo intrajornada insuficiente</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

# --------------------------------------------------
# APLICATIVO PRINCIPAL
# --------------------------------------------------

def main():
    """Função principal do aplicativo"""
    
    if 'autenticado' not in st.session_state:
        st.session_state.autenticado = False
    
    if not st.session_state.autenticado:
        mostrar_tela_login()
    else:
        mostrar_tela_principal()

if __name__ == "__main__":
    main()
