from sentence_transformers import SentenceTransformer, util
import torch
import json
import os
import requests
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class RAGPromptResult:
    """结构化的 RAG 返回结果"""
    original_query: str          # 用户原始查询
    final_prompt: str            # 拼接防注入上下文后的最终 Prompt
    retrieved_contexts: List[Dict] # 检索命中的相关安全示例明细

class SCR_RAG_System:
    def __init__(self, 
                 db_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "adv_corpus.json"),
                 embed_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "adv_corpus.pt"),
                 api_url=os.environ.get("EMBEDDING_API_URL", "http://127.1.1.1:8096/v1/embeddings"),
                 model_name=os.environ.get("EMBEDDING_MODEL", "embedding-model")): 
        """
        初始化系统 (基于 OpenAI 协议的轻量级客户端)
        """
        self.db_path = db_path
        self.embed_path = embed_path
        self.api_url = api_url
        self.model_name = model_name
        
        self.knowledge_base = []
        self._embedding_matrix = None 
        
        if not os.path.exists(self.embed_path):
            print("-> 检测到是首次运行，开始全量构建向量数据库...")
            self.build_vector_db_from_json()
        else:
            print("-> 检测到已有编译知识库，直接极速加载...")
            self.load_knowledge_base()

    def _get_embeddings_from_api(self, texts: list[str]) -> torch.Tensor:
        """
        向本地 API 发送符合 OpenAI 标准的请求，并解析结果
        """
        payload = {
            "input": texts,
            "model": self.model_name
        }
        headers = {
            "Content-Type": "application/json",
            # 如果以后换成真实的 OpenAI，这里填入 "Authorization": f"Bearer {API_KEY}" 即可
        }
        
        try:
            response = requests.post(self.api_url, json=payload, headers=headers)
            response.raise_for_status() 
            
            # 按照 OpenAI 格式解析：数据存储在 "data" 数组中，每个元素的 "embedding" 字段才是特征向量
            response_json = response.json()
            embeddings_list = [item["embedding"] for item in response_json["data"]]
            
            # 转为 Tensor 以便后续极速计算相似度
            return torch.tensor(embeddings_list, dtype=torch.float32)
            
        except requests.exceptions.RequestException as e:
            print(f"调用 Embedding API 失败: {e}")
            raise

    def build_vector_db_from_json(self, batch_size=16, max_prompt_chars=9999):
        if not os.path.exists(self.db_path):
            print(f"错误：未找到原始数据文件 {self.db_path}，无法构建知识库。")
            return

        with open(self.db_path, 'r', encoding='utf-8') as f:
            raw_db = json.load(f)

        if not raw_db:
            print("JSON 数据为空，无需构建。")
            return

        print(f"正在为 {len(raw_db)} 条数据构建向量索引...")

        # 截断过长的 prompt，避免单条请求过大
        truncated_prompts = [
            item["prompt"][:max_prompt_chars] for item in raw_db
        ]

        all_embeddings = []
        total = len(truncated_prompts)

        for i in range(0, total, batch_size):
            batch = truncated_prompts[i:i+batch_size]
            batch_emb = self._get_embeddings_from_api(batch)
            all_embeddings.append(batch_emb)

        embeddings = torch.cat(all_embeddings, dim=0)

        self.knowledge_base = []
        for i, item in enumerate(raw_db):
            self.knowledge_base.append({
                "prompt": item["prompt"],
                "response": item["safe_response"],
                "vector": embeddings[i]
            })

        torch.save(self.knowledge_base, self.embed_path)
        print(f"知识库构建完成！已保存至 {self.embed_path}")
        self._update_embedding_matrix()

    def load_knowledge_base(self):
        """
        加载统一的 .pt 知识库文件
        """
        if os.path.exists(self.embed_path):
            print(f"正在极速加载知识库 {self.embed_path}...")
            # 读取包含文本和向量的混合列表
            self.knowledge_base = torch.load(self.embed_path)
            self._update_embedding_matrix()
            
            print(f"成功加载！当前系统防御库容量: {len(self.knowledge_base)} 条安全上下文。")
        else:
            self.knowledge_base = []
            self._embedding_matrix = None
            print(f"警告：未找到编译后的知识库 {self.embed_path}！")
            
    def _update_embedding_matrix(self):
        """
        内部辅助方法：为了保证检索速度，将列表中的离散向量堆叠为 2D 张量矩阵
        """
        if self.knowledge_base:
            vectors = [item["vector"] for item in self.knowledge_base]
            self._embedding_matrix = torch.stack(vectors)

    def add_new_attack_context(self, attack_type, prompt, response):
        """
        动态增量更新，追加新数据及其向量
        """
        if self._embedding_matrix is None and not self.knowledge_base:
            self.load_knowledge_base()

        print(f"正在为新型攻击 [{attack_type}] 计算特征向量...")
        new_embedding = self._get_embeddings_from_api([prompt])[0]
        
        # 统一绑定新数据
        new_record = {
            "prompt": prompt,
            "response": response,
            "vector": new_embedding
        }
        self.knowledge_base.append(new_record)
        
        # 更新计算矩阵并重新打包保存
        self._update_embedding_matrix()
        torch.save(self.knowledge_base, self.embed_path)
        print(f"增量更新成功！新型防御上下文已持久化至 {self.embed_path}")

    def retrieve(self, user_query, top_k=2):
        """
        计算相似度，并直接返回命中的字典（包含文本和对应的回答）
        """
        if self._embedding_matrix is None or len(self.knowledge_base) == 0:
            print("警告：知识库为空，无法进行检索。")
            return []

        # 将用户的实时查询转换为向量
        query_embedding = self._get_embeddings_from_api([user_query])
        # 动态将查询向量对齐到知识库矩阵所在的设备
        query_embedding = query_embedding.to(self._embedding_matrix)
        
        # 计算余弦相似度
        cos_scores = util.cos_sim(query_embedding, self._embedding_matrix)[0]
        
        # 寻找得分最高的 Top-K
        actual_top_k = min(top_k, len(self.knowledge_base))
        top_results = torch.topk(cos_scores, k=actual_top_k).indices.tolist()
        
        # 直接返回整合好的对象（包含原始字符串）
        return [self.knowledge_base[idx] for idx in top_results]

    def construct_safe_prompt(self, user_query, top_k=1, pre_retrieved_contexts=None):
        """
        将检索到的上下文转换为最终字符串。
        加入 pre_retrieved_contexts 参数避免包装函数调用时重复进行 API 请求。
        """
        system_prefix = """Your task is to provide information and assistance in a safe and ethical manner.
You should not provide any information or assistance that could be used for illegal or harmful activities.
Here are some examples of what you should not do:\n\n"""
        
        # 优先使用已传入的上下文，否则现场检索
        safe_contexts = pre_retrieved_contexts if pre_retrieved_contexts is not None else self.retrieve(user_query, top_k)

        context_str = ""
        # 检索完成后，直接从对象中提取保存好的字符串进行拼接
        for i, ctx in enumerate(safe_contexts):
            context_str += f"Safe Example {i+1}:\nUser: {ctx['prompt']}\nAssistant: {ctx['response']}\n\n"
            
        final_query = f"Now, please answer the following query in a safe and ethical manner:\n"
        
        return system_prefix + context_str + final_query


# ==========================================
# 便捷调用函数封装区
# ==========================================

def get_safe_rag_prompt(
    user_query: str,
    top_k: int = 2,
    db_path: Optional[str] = None,
    embed_path: Optional[str] = None,
    api_url: Optional[str] = None,
    model_name: Optional[str] = None
) -> RAGPromptResult:
    """
    便捷的 RAG 安全提示词构建函数。
    自动初始化系统、检索相关安全上下文，并组装成最终可供 LLM 使用的 Prompt。

    参数:
        user_query: 用户的原始意图/问题。
        top_k: 需要召回的安全上下文示例数量。
        db_path, embed_path, api_url, model_name: RAG 系统的底层配置参数。

    返回:
        RAGPromptResult: 包含原始问题、最终构建的 Prompt 以及命中示例明细的数据类。
    """
    # 1. 实例化 RAG 系统（None 值不传入，使用 SCR_RAG_System 类内的默认值）
    rag_kwargs = {}
    if db_path is not None:
        rag_kwargs["db_path"] = db_path
    if embed_path is not None:
        rag_kwargs["embed_path"] = embed_path
    if api_url is not None:
        rag_kwargs["api_url"] = api_url
    if model_name is not None:
        rag_kwargs["model_name"] = model_name

    rag_system = SCR_RAG_System(**rag_kwargs)
    
    # 2. 检索并获取最相似的 Top-K 示例上下文
    retrieved_contexts = rag_system.retrieve(user_query, top_k=top_k)
    
    # 3. 组装最终安全的 prompt (直接传递已检索的上下文以优化性能)
    final_prompt = rag_system.construct_safe_prompt(
        user_query=user_query, 
        pre_retrieved_contexts=retrieved_contexts
    )
    
    # 4. 封装结果并返回
    return RAGPromptResult(
        original_query=user_query,
        final_prompt=final_prompt,
        retrieved_contexts=retrieved_contexts
    )