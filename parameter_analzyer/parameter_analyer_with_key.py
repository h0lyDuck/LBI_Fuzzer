import os
import getpass
import hashlib
import json
from tqdm import *
from langchain_community.document_loaders.generic import GenericLoader
from langchain_community.document_loaders.parsers import LanguageParser
from langchain_community.chat_message_histories import ChatMessageHistory
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.text_splitter import Language
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain.chains.history_aware_retriever import create_history_aware_retriever
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableWithMessageHistory


class JSParserByLLM:
    def __init__(self, target_path, question_list, llm="DeepSeek"):
        self.question_list = question_list
        self.actually_question_prompt = None
        self.contextualize_question_prompt = None
        self.target_path = target_path
        self.vector_db_path = self.target_path + "/vector_db"
        self.target_path_file_list = []
        self.vectordb = None
        self.store = {}

        if llm == "DeepSeek":
            # self.llm = ChatOpenAI(
            #     model="deepseek-chat",
            #     openai_api_key="",
            #     openai_api_base="https://api.deepseek.com",
            # )
            self.llm = ChatOpenAI(
                model="ep-20250207181335-gwrnn",
                openai_api_key="4980081a-2d42-4335-b5aa-1bb6cb697d6c",
                openai_api_base="https://ark.cn-beijing.volces.com/api/v3",
            )
        elif llm == "OpenAI":
            self.llm = ChatOpenAI(
                model="gpt-4o-mini",
                openai_api_base="https://api.gptsapi.net/v1",
                openai_api_key="sk-Julfd146854e2a2ed77764703248827226471315694eVkkY",
            )

        self.update_target_path_file_list()
        self.get_contextualize_question_prompt()
        self.get_actually_question_prompt()
        self.vector_db_init(self.target_path)

    def get_contextualize_question_prompt(self):
        system_prompt = (
            "Please rephrase the user's final question based on the chat history and the user's last query.\n"
            "You only need to rephrase the user's final question; do not answer the question.\n"
            "If there is no chat history, return the user's question directly; if there is chat history, rephrase it "
            "accordingly.\n"
            "NOTICE:Provide only the rephrased question without any additional elements."
        )
        contextualize_question_prompt = ChatPromptTemplate(
            [
                ("system", system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )
        self.contextualize_question_prompt = contextualize_question_prompt

    def get_actually_question_prompt(self):
        system_prompt = (
            "You are an expert in code analysis, familiar with JavaScript. "
            "You are capable of analyzing and understanding the communication between JavaScript and backend services, "
            "including the communication URLs, methods, and parameters."
            "\n\n"
            "I will provide you with Javascript code, which is used for communication between the front-end "
            "management interface and the back-end service of a router device."
            "\n\n"
            "{context}"
            "\n\n"
            "NOTICE:"
            "\n\n"
            "1.Only provide a JSON result, without any markdown syntax ,such as ``````.\n"
            "2.If you don't know the answer, please return []. \n"
            "3.If the provided JavaScript code does not contain any backend communication URLs, methods, or parameters, please return []. \n"
            "4.Ensure your analysis is accurate and comprehensive. Avoid speculation and unsupported claims.\n"
            "5.Ensure that the JSON value pairs is valid and not contain JavaScript code.\n"
        )

        actually_question_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", system_prompt),
                MessagesPlaceholder("chat_history"),
                ("human", "{input}"),
            ]
        )
        self.actually_question_prompt = actually_question_prompt

    def update_target_path_file_list(self):
        file_list = []
        for root, dirs, files in os.walk(self.target_path):
            if "vector_db" in root or "res" in root:
                continue
            for file in files:
                file_path = os.path.join(root, file)
                file_list.append(file_path)
        self.target_path_file_list = file_list

    def is_document_exists(self, document_hash, document_source):
        existing_docs = self.vectordb.get(
            where={
                "$and": [{"document_hash": document_hash}, {"source": document_source}]
            }
        )
        return len(existing_docs["ids"]) > 0

    def insert_document_if_not_exists(self, document):
        document_hash = hashlib.md5(document.page_content.encode("utf-8")).hexdigest()
        document_source = document.metadata["source"]
        if not self.is_document_exists(document_hash, document_source):
            document.metadata["document_hash"] = document_hash
            self.vectordb.add_documents([document])

    def vector_db_init(self, dic_path="test"):
        # os.environ["OPENAI_API_KEY"] = getpass.getpass()
        # os.environ["OPENAI_API_KEY"] = (
        #     "sk-Julfd146854e2a2ed77764703248827226471315694eVkkY"
        # )
        self.vectordb = Chroma(
            embedding_function=OpenAIEmbeddings(
                openai_api_base="https://api.gptsapi.net/v1",
                model="text-embedding-3-large",
                openai_api_key="sk-Julfd146854e2a2ed77764703248827226471315694eVkkY",
            ),
            persist_directory=self.vector_db_path,
        )

        # loader这里for循环读文件，对于大文件，或者风快
        loader = GenericLoader.from_filesystem(
            path=os.path.join(os.getcwd(), dic_path),
            glob="**/*",
            suffixes=[".js"],
            parser=LanguageParser(language="js"),
        )
        oringnal_documents = loader.load()
        documents_splitter = RecursiveCharacterTextSplitter.from_language(
            language=Language.JS, chunk_size=2000, chunk_overlap=200
        )

        documents = documents_splitter.split_documents(oringnal_documents)
        for document in tqdm(documents):
            # print(document)
            self.insert_document_if_not_exists(document)

    def get_session_history(self, session_id: str) -> ChatMessageHistory:
        if session_id not in self.store:
            self.store[session_id] = ChatMessageHistory()
        return self.store[session_id]

    def parse_js_argument_by_llm(self, file_path):
        """
        使用LLM解析JavaScript文件中的参数

        :param file_path: JavaScript文件的路径
        :return: 解析结果
        """
        # 打印存储信息
        self.store = {}

        # 创建一个检索器，用于从向量数据库中检索与文件路径相关的文档
        retriever = self.vectordb.as_retriever(
            search_kwargs={"filter": {"source": file_path}, "k": 15}
        )

        # 创建一个历史感知检索器，用于根据聊天历史和上下文重新表述问题
        history_aware_retriever = create_history_aware_retriever(
            self.llm, retriever, self.contextualize_question_prompt
        )

        # 创建一个文档链，用于处理检索到的文档并生成回答
        question_answer_chain = create_stuff_documents_chain(
            self.llm, self.actually_question_prompt
        )

        # 创建一个检索链，用于结合历史感知检索器和文档链
        rag_chain = create_retrieval_chain(
            history_aware_retriever, question_answer_chain
        )

        # 创建一个可运行的历史感知链，用于处理对话历史和输入问题
        conversational_rag_chain = RunnableWithMessageHistory(
            rag_chain,
            self.get_session_history,
            input_messages_key="input",
            history_messages_key="chat_history",
            output_messages_key="answer",
        )

        # 创建一个可运行的历史感知链，用于处理上下文问题和LLM
        contextualize_question_chain = RunnableWithMessageHistory(
            self.contextualize_question_prompt | self.llm,
            self.get_session_history,
            input_messages_key="input",
            history_messages_key="chat_history",
        )

        answer = []
        # 遍历问题列表
        print(
            "##############################################################################################################"
        )
        print(f"  Target File: {os.path.basename(file_path)}")
        for question in self.question_list:
            print(
                "##############################################################################################################"
            )
            # 使用上下文问题链处理原始问题，生成优化后的问题
            print(f"  Original Question: {question}")
            res = contextualize_question_chain.invoke(
                {"input": question},
                config={"configurable": {"session_id": "optimize_question"}},
            )
            print(f"  Rephrased Question: {res.content}")
            # 使用对话检索链处理优化后的问题，生成回答
            res = conversational_rag_chain.invoke(
                {"input": res.content},
                config={"configurable": {"session_id": "actual_question"}},
            )
            print(f"  Stage Answer: {res['answer']}")
            # 将回答添加到答案列表中
            answer.append(res["answer"])
        f_answer = (
            answer[1].replace("```json", "").replace("```JSON", "").replace("```", "")
        )
        print(
            "##############################################################################################################"
        )
        print(f"  Final result: {f_answer}")
        print(
            "##############################################################################################################"
        )
        return f_answer

    def batch_parse_js_arguments(self):
        res = []
        for file_path in tqdm(self.target_path_file_list):
            file_path = os.path.join(os.getcwd(), file_path)
            # print("Parsing file: " + file_path)
            temp = self.parse_js_argument_by_llm(file_path)
            print(f"[+] FileName: {file_path} res:")
            print(temp)
            res += json.loads(temp)
        os.makedirs(os.path.join(self.target_path, "res"), exist_ok=True)
        with open(os.path.join(self.target_path, "res", "res.json"), "w") as f:
            f.write(json.dumps(res))
            # f.write("[\n")
            # for i in res:
            #     f.write(json.dumps(i) + ",\n")
            # f.write("]\n")
            # temp = json.loads(i)
            # print("[+] temp:  ")
            # print(temp)
        # retriever = self.vectordb.as_retriever(
        #     search_kwargs={"filter": {"source": file_path}, "k": 10}
        # )
        # history_aware_retriever = create_history_aware_retriever(
        #     self.llm, retriever, self.contextualize_question_prompt
        # )


if __name__ == "__main__":
    question_list = [
        "Extract a list from the provided JavaScript code, including the URLs for backend communication and the "
        'communication methods. List format like this: [{"method": "", "url": ""}]',
        "Analyze the parameter names required by the extracted URLs and form a list accordingly, which contains "
        'URLs, method and parameter names. List format like this: [{"method": "", "url": "","parameters": []}]',
    ]
    JSParser = JSParserByLLM("tenda_ac9_js", question_list)
    # JSParser = JSParserByLLM("lblink_ac1900_js", question_list)
    # JSParser = JSParserByLLM("test", question_list)
    # JSParser = JSParserByLLM("test", question_list, "OpenAI")

    JSParser.batch_parse_js_arguments()
    # JSParser.parse_js_argument_by_llm(
    #     os.path.join(os.getcwd(), "tenda_ac9_js/pptp_server.js")
    # )
