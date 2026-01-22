# Python Conventions and Best Practices

A comprehensive guide to writing Pythonic, maintainable, and efficient Python code following PEP 8 and modern Python practices.

## Code Style and Structure

### PEP 8 Compliance and Beyond

```python
"""
Module docstring: Brief description of the module.

This module provides utilities for user management including
authentication, authorization, and profile management.
"""

import os
import sys
from typing import Dict, List, Optional, Union, Any, Protocol
from dataclasses import dataclass, field
from pathlib import Path
import logging

# Third-party imports
import requests
from sqlalchemy import create_engine
from pydantic import BaseModel, validator

# Local imports
from .models import User, UserRole
from .exceptions import UserNotFoundError, ValidationError

# Module-level constants
DEFAULT_TIMEOUT = 30
MAX_RETRY_ATTEMPTS = 3
SUPPORTED_FORMATS = ['json', 'xml', 'csv']

logger = logging.getLogger(__name__)


@dataclass
class UserConfig:
    """Configuration for user management operations."""
    
    timeout: int = DEFAULT_TIMEOUT
    max_retries: int = MAX_RETRY_ATTEMPTS
    supported_formats: List[str] = field(default_factory=lambda: SUPPORTED_FORMATS.copy())
    
    def __post_init__(self) -> None:
        """Validate configuration after initialization."""
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        if self.max_retries < 0:
            raise ValueError("Max retries cannot be negative")


class UserService:
    """Service for managing user operations.
    
    This class provides methods for creating, updating, and retrieving
    user information with proper error handling and logging.
    
    Attributes:
        config: Configuration object for the service
        _session: HTTP session for API calls
    """
    
    def __init__(self, config: UserConfig) -> None:
        """Initialize the user service.
        
        Args:
            config: Configuration object for the service
            
        Raises:
            ValueError: If configuration is invalid
        """
        self.config = config
        self._session = requests.Session()
        self._session.timeout = config.timeout
        
        logger.info("UserService initialized with timeout=%d", config.timeout)
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Retrieve a user by ID.
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            User object if found, None otherwise
            
        Raises:
            ValidationError: If user_id is invalid
            UserNotFoundError: If user doesn't exist
        """
        if not user_id or not isinstance(user_id, str):
            raise ValidationError("User ID must be a non-empty string")
        
        try:
            response = self._make_request('GET', f'/users/{user_id}')
            return User.from_dict(response.json()) if response else None
        except requests.RequestException as e:
            logger.error("Failed to retrieve user %s: %s", user_id, e)
            raise UserNotFoundError(f"User {user_id} not found") from e
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request with retry logic.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint
            **kwargs: Additional arguments for the request
            
        Returns:
            Response object
            
        Raises:
            requests.RequestException: If request fails after all retries
        """
        for attempt in range(self.config.max_retries + 1):
            try:
                response = self._session.request(method, endpoint, **kwargs)
                response.raise_for_status()
                return response
            except requests.RequestException as e:
                if attempt == self.config.max_retries:
                    raise
                logger.warning(
                    "Request failed (attempt %d/%d): %s", 
                    attempt + 1, self.config.max_retries + 1, e
                )
```

### Type Hints and Protocols

```python
from typing import Protocol, TypeVar, Generic, Callable, Awaitable
from abc import ABC, abstractmethod

# Protocol for duck typing
class Drawable(Protocol):
    """Protocol for objects that can be drawn."""
    
    def draw(self) -> None:
        """Draw the object."""
        ...
    
    def get_area(self) -> float:
        """Get the area of the object."""
        ...


# Generic types
T = TypeVar('T')
K = TypeVar('K')
V = TypeVar('V')

class Repository(Generic[T], ABC):
    """Abstract base class for repositories."""
    
    @abstractmethod
    async def get(self, id: str) -> Optional[T]:
        """Get an entity by ID."""
        ...
    
    @abstractmethod
    async def save(self, entity: T) -> T:
        """Save an entity."""
        ...
    
    @abstractmethod
    async def delete(self, id: str) -> bool:
        """Delete an entity by ID."""
        ...


class UserRepository(Repository[User]):
    """Repository for user entities."""
    
    def __init__(self, db_session: Any) -> None:
        self.db_session = db_session
    
    async def get(self, id: str) -> Optional[User]:
        """Get a user by ID."""
        # Implementation here
        pass
    
    async def save(self, user: User) -> User:
        """Save a user."""
        # Implementation here
        pass
    
    async def delete(self, id: str) -> bool:
        """Delete a user by ID."""
        # Implementation here
        pass
    
    async def find_by_email(self, email: str) -> Optional[User]:
        """Find a user by email address."""
        # Implementation here
        pass


# Callable types for higher-order functions
ProcessorFunc = Callable[[T], T]
AsyncProcessorFunc = Callable[[T], Awaitable[T]]

def apply_processors(data: T, processors: List[ProcessorFunc[T]]) -> T:
    """Apply a list of processors to data."""
    result = data
    for processor in processors:
        result = processor(result)
    return result
```

## Error Handling and Exceptions

### Custom Exception Hierarchy

```python
class AppError(Exception):
    """Base exception class for application errors."""
    
    def __init__(self, message: str, code: Optional[str] = None, 
                 context: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__.upper()
        self.context = context or {}
    
    def __str__(self) -> str:
        return f"{self.code}: {self.message}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for serialization."""
        return {
            'error': self.code,
            'message': self.message,
            'context': self.context
        }


class ValidationError(AppError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, 
                 value: Any = None) -> None:
        context = {}
        if field:
            context['field'] = field
        if value is not None:
            context['value'] = str(value)
        
        super().__init__(message, 'VALIDATION_ERROR', context)
        self.field = field
        self.value = value


class BusinessLogicError(AppError):
    """Raised when business logic constraints are violated."""
    pass


class ExternalServiceError(AppError):
    """Raised when external service calls fail."""
    
    def __init__(self, message: str, service: str, status_code: Optional[int] = None) -> None:
        context = {'service': service}
        if status_code:
            context['status_code'] = status_code
        
        super().__init__(message, 'EXTERNAL_SERVICE_ERROR', context)
        self.service = service
        self.status_code = status_code


# Context manager for error handling
from contextlib import contextmanager
from typing import Iterator, Type, Union

@contextmanager
def handle_errors(
    *exception_types: Type[Exception],
    default_return: Any = None,
    log_errors: bool = True
) -> Iterator[None]:
    """Context manager for graceful error handling.
    
    Args:
        *exception_types: Exception types to catch
        default_return: Value to return on error
        log_errors: Whether to log caught exceptions
    """
    try:
        yield
    except exception_types as e:
        if log_errors:
            logger.exception("Error occurred: %s", e)
        return default_return


# Usage example
def safe_divide(a: float, b: float) -> Optional[float]:
    """Safely divide two numbers."""
    with handle_errors(ZeroDivisionError, ValueError):
        return a / b
    return None
```

### Result Pattern for Error Handling

```python
from typing import Union, Callable, TypeVar
from dataclasses import dataclass

T = TypeVar('T')
E = TypeVar('E')
U = TypeVar('U')

@dataclass(frozen=True)
class Success:
    """Represents a successful result."""
    value: Any
    
    def is_success(self) -> bool:
        return True
    
    def is_failure(self) -> bool:
        return False
    
    def map(self, func: Callable[[Any], U]) -> 'Result[U, Any]':
        """Apply function to the success value."""
        try:
            return Success(func(self.value))
        except Exception as e:
            return Failure(e)
    
    def flat_map(self, func: Callable[[Any], 'Result[U, Any]']) -> 'Result[U, Any]':
        """Apply function that returns a Result."""
        try:
            return func(self.value)
        except Exception as e:
            return Failure(e)


@dataclass(frozen=True)
class Failure:
    """Represents a failed result."""
    error: Any
    
    def is_success(self) -> bool:
        return False
    
    def is_failure(self) -> bool:
        return True
    
    def map(self, func: Callable[[Any], U]) -> 'Result[Any, Any]':
        """Return self for failed results."""
        return self
    
    def flat_map(self, func: Callable[[Any], 'Result[U, Any]']) -> 'Result[Any, Any]':
        """Return self for failed results."""
        return self


Result = Union[Success, Failure]

def safe_operation(func: Callable[[], T]) -> Result:
    """Execute function and return Result."""
    try:
        return Success(func())
    except Exception as e:
        return Failure(e)


# Usage example
def divide_numbers(a: float, b: float) -> Result:
    """Divide two numbers safely."""
    if b == 0:
        return Failure(ValueError("Division by zero"))
    return Success(a / b)

def process_division(a: float, b: float) -> str:
    """Process division and return formatted result."""
    result = divide_numbers(a, b)
    
    if result.is_success():
        return f"Result: {result.value:.2f}"
    else:
        return f"Error: {result.error}"
```

## Async/Await Patterns

### Async Best Practices

```python
import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)

class AsyncUserService:
    """Async service for user operations."""
    
    def __init__(self, base_url: str, timeout: int = 30) -> None:
        self.base_url = base_url
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self) -> 'AsyncUserService':
        """Async context manager entry."""
        self._session = aiohttp.ClientSession(timeout=self.timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._session:
            await self._session.close()
    
    @asynccontextmanager
    async def session(self):
        """Context manager for HTTP session."""
        if self._session is None:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                self._session = session
                try:
                    yield session
                finally:
                    self._session = None
        else:
            yield self._session
    
    async def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get a single user."""
        async with self.session() as session:
            try:
                async with session.get(f"{self.base_url}/users/{user_id}") as response:
                    if response.status == 200:
                        return await response.json()
                    elif response.status == 404:
                        return None
                    else:
                        response.raise_for_status()
            except aiohttp.ClientError as e:
                logger.error("Failed to get user %s: %s", user_id, e)
                raise ExternalServiceError(f"Failed to get user {user_id}", "user_api")
    
    async def get_users_batch(self, user_ids: List[str]) -> List[Optional[Dict[str, Any]]]:
        """Get multiple users concurrently."""
        tasks = [self.get_user(user_id) for user_id in user_ids]
        return await asyncio.gather(*tasks, return_exceptions=False)
    
    async def get_users_with_semaphore(
        self, 
        user_ids: List[str], 
        max_concurrent: int = 10
    ) -> List[Optional[Dict[str, Any]]]:
        """Get multiple users with concurrency control."""
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def get_user_with_semaphore(user_id: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await self.get_user(user_id)
        
        tasks = [get_user_with_semaphore(user_id) for user_id in user_ids]
        return await asyncio.gather(*tasks)


# Async retry decorator
from functools import wraps
import random

def async_retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,)
):
    """Decorator for async function retry logic."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        raise
                    
                    wait_time = delay * (backoff ** attempt) + random.uniform(0, 1)
                    logger.warning(
                        "Attempt %d failed for %s: %s. Retrying in %.2fs",
                        attempt + 1, func.__name__, e, wait_time
                    )
                    await asyncio.sleep(wait_time)
            
            raise last_exception
        return wrapper
    return decorator


# Usage example
@async_retry(max_attempts=3, delay=1.0, exceptions=(aiohttp.ClientError,))
async def fetch_data(url: str) -> Dict[str, Any]:
    """Fetch data from URL with retry logic."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            response.raise_for_status()
            return await response.json()
```

## Data Classes and Pydantic Models

### Advanced Data Modeling

```python
from dataclasses import dataclass, field, InitVar
from typing import List, Dict, Optional, ClassVar
from datetime import datetime, timezone
from enum import Enum, auto
import uuid

class UserRole(Enum):
    """User role enumeration."""
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"
    GUEST = "guest"


class UserStatus(Enum):
    """User status enumeration."""
    ACTIVE = auto()
    INACTIVE = auto()
    SUSPENDED = auto()
    DELETED = auto()


@dataclass(frozen=True)
class Address:
    """Immutable address data class."""
    street: str
    city: str
    state: str
    zip_code: str
    country: str = "US"
    
    def __post_init__(self) -> None:
        """Validate address data."""
        if not self.zip_code.isdigit() or len(self.zip_code) != 5:
            raise ValidationError("Invalid ZIP code format")


@dataclass
class User:
    """User data class with validation and computed properties."""
    
    # Class variable
    _id_counter: ClassVar[int] = 0
    
    # Required fields
    email: str
    name: str
    
    # Optional fields with defaults
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Fields excluded from init
    id: str = field(init=False)
    full_name: str = field(init=False)
    
    # Fields excluded from repr
    password_hash: Optional[str] = field(default=None, repr=False)
    
    # Collections with factory
    addresses: List[Address] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # InitVar for initialization-only data
    password: InitVar[Optional[str]] = None
    
    def __post_init__(self, password: Optional[str]) -> None:
        """Post-initialization processing."""
        # Generate unique ID
        User._id_counter += 1
        self.id = f"user_{User._id_counter:06d}"
        
        # Set computed fields
        self.full_name = self.name.title()
        
        # Hash password if provided
        if password:
            self.password_hash = self._hash_password(password)
        
        # Validate email
        if "@" not in self.email:
            raise ValidationError("Invalid email format", field="email", value=self.email)
    
    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password (simplified for example)."""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    
    @property
    def is_admin(self) -> bool:
        """Check if user is an admin."""
        return self.role == UserRole.ADMIN
    
    @property
    def is_active(self) -> bool:
        """Check if user is active."""
        return self.status == UserStatus.ACTIVE
    
    def add_address(self, address: Address) -> None:
        """Add an address to the user."""
        if address not in self.addresses:
            self.addresses.append(address)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'full_name': self.full_name,
            'role': self.role.value,
            'status': self.status.name,
            'created_at': self.created_at.isoformat(),
            'addresses': [
                {
                    'street': addr.street,
                    'city': addr.city,
                    'state': addr.state,
                    'zip_code': addr.zip_code,
                    'country': addr.country
                }
                for addr in self.addresses
            ],
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create user from dictionary."""
        # Parse datetime
        created_at = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        
        # Parse addresses
        addresses = [
            Address(**addr_data) for addr_data in data.get('addresses', [])
        ]
        
        return cls(
            email=data['email'],
            name=data['name'],
            role=UserRole(data['role']),
            status=UserStatus[data['status']],
            created_at=created_at,
            addresses=addresses,
            metadata=data.get('metadata', {})
        )
```

### Pydantic Models for Validation

```python
from pydantic import BaseModel, validator, root_validator, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime
import re

class AddressModel(BaseModel):
    """Pydantic model for address validation."""
    
    street: str = Field(..., min_length=1, max_length=200)
    city: str = Field(..., min_length=1, max_length=100)
    state: str = Field(..., min_length=2, max_length=2)
    zip_code: str = Field(..., regex=r'^\d{5}(-\d{4})?$')
    country: str = Field(default="US", min_length=2, max_length=2)
    
    @validator('state')
    def validate_state(cls, v):
        """Validate state code."""
        if not v.isupper():
            raise ValueError('State must be uppercase')
        return v
    
    @validator('country')
    def validate_country(cls, v):
        """Validate country code."""
        if not v.isupper():
            raise ValueError('Country must be uppercase')
        return v


class UserCreateModel(BaseModel):
    """Model for user creation validation."""
    
    email: EmailStr
    name: str = Field(..., min_length=1, max_length=100)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.USER
    addresses: List[AddressModel] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain digit')
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError('Password must contain special character')
        return v
    
    @validator('name')
    def validate_name(cls, v):
        """Validate name format."""
        if not re.match(r'^[a-zA-Z\s\-\'\.]+$', v):
            raise ValueError('Name contains invalid characters')
        return v.strip()
    
    @root_validator
    def validate_admin_role(cls, values):
        """Validate admin role assignment."""
        role = values.get('role')
        email = values.get('email')
        
        if role == UserRole.ADMIN and email and not email.endswith('@company.com'):
            raise ValueError('Admin role requires company email')
        
        return values
    
    class Config:
        """Pydantic configuration."""
        use_enum_values = True
        validate_assignment = True
        extra = 'forbid'  # Forbid extra fields


class UserResponseModel(BaseModel):
    """Model for user response serialization."""
    
    id: str
    email: EmailStr
    name: str
    full_name: str
    role: UserRole
    status: UserStatus
    created_at: datetime
    addresses: List[AddressModel]
    metadata: Dict[str, Any]
    
    class Config:
        """Pydantic configuration."""
        orm_mode = True  # Allow creation from ORM objects
        use_enum_values = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# Usage with FastAPI
from fastapi import FastAPI, HTTPException, Depends

app = FastAPI()

@app.post("/users", response_model=UserResponseModel)
async def create_user(user_data: UserCreateModel) -> UserResponseModel:
    """Create a new user."""
    try:
        # Convert Pydantic model to dataclass
        user = User(
            email=user_data.email,
            name=user_data.name,
            role=user_data.role,
            password=user_data.password
        )
        
        # Add addresses
        for addr_data in user_data.addresses:
            address = Address(**addr_data.dict())
            user.add_address(address)
        
        # Save user (implementation depends on your storage)
        # saved_user = await user_repository.save(user)
        
        return UserResponseModel.from_orm(user)
    
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

Remember: Python's strength lies in its readability and expressiveness. Write code that tells a story, use meaningful names, follow conventions consistently, and leverage Python's rich standard library and type system to create robust, maintainable applications.