import os
import tiktoken
from typing import Any, Dict
from llama_index.core.callbacks import CallbackManager, TokenCountingHandler
from llama_index.core import Settings

try:
    from llama_index.llms.deepseek import DeepSeek
except ImportError:
    DeepSeek = None

try:
    from llama_index.llms.openai import OpenAI
except ImportError:
    OpenAI = None

try:
    from llama_index.llms.azure_openai import AzureOpenAI
except ImportError:
    AzureOpenAI = None


def build_token_counter() -> TokenCountingHandler:
    """Build a token counter for tracking LLM usage"""
    try:
        enc = tiktoken.get_encoding("cl100k_base")
        return TokenCountingHandler(tokenizer=enc.encode)
    except Exception:
        # Fallback: approximate with UTF-8 bytes length
        return TokenCountingHandler(tokenizer=lambda s: list(s.encode("utf-8")))


def create_llm(
    model: str,
    api_key: str,
    base_url: str,
    temperature: float = 0.2,
    timeout: float = 120.0,
    max_retries: int = 2
) -> Any:
    """Create LLM instance based on model name"""
    
    model_lower = model.lower()
    
    # Qwen/QwQ models - use gpt-4o-mini as fallback for metadata
    if "qwq" in model_lower or "qwen" in model_lower:
        if OpenAI is None:
            raise ImportError("openai package is required for QwQ models")
        
        # Create OpenAI client but override model metadata to avoid validation issues
        llm = OpenAI(
            api_key=api_key,
            api_base=base_url,
            model="gpt-4o-mini",  # Use recognized model for metadata
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )
        # Override the actual model name used in requests
        llm._model = model
        return llm
    
    # DeepSeek models
    elif "deepseek" in model_lower:
        if DeepSeek is None:
            raise ImportError("llama-index-llms-deepseek package is required for DeepSeek models")
        return DeepSeek(
            api_key=api_key,
            api_base=base_url,
            model=model,
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )
    
    # GPT models
    elif "gpt" in model_lower:
        if "azure" in base_url.lower():
            if AzureOpenAI is None:
                raise ImportError("azure-openai package is required for Azure OpenAI")
            return AzureOpenAI(
                engine=model,
                model=model,
                azure_endpoint=base_url,
                api_key=api_key,
                api_version=os.environ.get("OPENAI_API_VERSION", "2024-03-01-preview"),
                timeout=timeout,
                max_retries=max_retries,
            )
        else:
            if OpenAI is None:
                raise ImportError("openai package is required for OpenAI models")
            return OpenAI(
                api_key=api_key,
                api_base=base_url,
                model=model,
                temperature=temperature,
                timeout=timeout,
                max_retries=max_retries,
            )
    
    # Default: try OpenAI-compatible API with gpt-4o-mini as fallback
    else:
        if OpenAI is None:
            raise ImportError("openai package is required for OpenAI-compatible models")
        
        llm = OpenAI(
            api_key=api_key,
            api_base=base_url,
            model="gpt-4o-mini",  # Use recognized model for metadata
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )
        # Override the actual model name used in requests
        llm._model = model
        return llm


def setup_llm_settings(
    model: str,
    api_key: str,
    base_url: str,
    temperature: float = 0.2,
    timeout: float = 120.0,
    max_retries: int = 2
) -> tuple[Any, TokenCountingHandler]:
    """Setup LLM and token counter for the application"""
    llm = create_llm(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries
    )
    
    token_counter = build_token_counter()
    
    Settings.llm = llm
    Settings.callback_manager = CallbackManager([token_counter])
    token_counter.reset_counts()
    
    return llm, token_counter 