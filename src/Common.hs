module Common (module Common, module X) where

import           Control.Applicative as X
import           Control.DeepSeq     as X (NFData (rnf))
import           Control.Exception   as X (ArithException (Overflow, Underflow), throw)
import           Control.Monad       as X
import           Control.Newtype     as X (Newtype (..))
import           Data.Bits           as X
import           Data.ByteString     as X (ByteString)
import           Data.Int            as X
import           Data.IntCast        as X
import           Data.List.NonEmpty  as X (NonEmpty (..))
import           Data.Maybe          as X
import           Data.Proxy          as X (Proxy (Proxy))
import           Data.Semigroup      as X
import           Data.Text.Short     as X (ShortText)
import           Data.Word           as X
import           GHC.Generics        as X (Generic)
import           GHC.TypeLits        as X

rwhnf :: a -> ()
rwhnf x = seq x ()
