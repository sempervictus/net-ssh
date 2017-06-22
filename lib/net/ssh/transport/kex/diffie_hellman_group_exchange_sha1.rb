require 'net/ssh/errors'
require 'net/ssh/transport/constants'
require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'

module Net::SSH::Transport::Kex

  # A key-exchange service implementing the
  # "diffie-hellman-group-exchange-sha1" key-exchange algorithm.
  class DiffieHellmanGroupExchangeSHA1 < DiffieHellmanGroup1SHA1
    MINIMUM_BITS      = 1024
    MAXIMUM_BITS      = 8192

    KEXDH_GEX_GROUP   = 31
    KEXDH_GEX_INIT    = 32
    KEXDH_GEX_REPLY   = 33
    KEXDH_GEX_REQUEST = 34

    private

      # Compute the number of bits needed for the given number of bytes.
      def compute_need_bits

        # for Compatibility: OpenSSH requires (need_bits * 2 + 1) length of parameter
        need_bits = data[:need_bytes] * 8 * 2 + 1

        data[:minimum_dh_bits] ||= MINIMUM_BITS

        if need_bits < data[:minimum_dh_bits]
          need_bits = data[:minimum_dh_bits]
        elsif need_bits > MAXIMUM_BITS
          need_bits = MAXIMUM_BITS
        end

        data[:need_bits ] = need_bits
        data[:need_bytes] = need_bits / 8
      end

      # Returns the DH key parameters for the given session.
      def get_parameters
        compute_need_bits

        puts "DH GROUP"
        if @server_side
          # Get number of bits requested
          buffer = connection.next_message
          # raise "#{buffer.read_string.split(/,/)}"
          unless buffer.type == KEXDH_GEX_REQUEST
            raise Net::SSH::Exception, "expected KEXDH_GEX_REQUEST, got #{buffer.type}"
          end
          gex_req = {}
          gex_req[:min_bits]  = buffer.read_bignum
          gex_req[:need_bits] = buffer.read_bignum
          gex_req[:max_bix]   = buffer.read_bignum
 
          # p = 99611606042252990125910583405322561369935541488765326562019858407977938995814201495326595653494701999530486575058397074595234955644812090829951395775588920011571953659422608721331999582799138737549592899140083883734263669831575847589539341121254896505442295613951466500930967890287116209674647250058690484763
          # g = 2
 
          # # should be keyes[min_bits]
          dh = OpenSSL::PKey::DH.new(data[:need_bits])
          buffer = Net::SSH::Buffer.from(:byte, KEXDH_GEX_GROUP) #, :long, dh.p, :long, dh.g)
          buffer.write_bignum(dh.p)
          buffer.write_bignum(dh.g)
          connection.send_message(buffer)

          g  = dh.g
          p  = dh.p
        else
          # request the DH key parameters for the given number of bits.
          buffer = Net::SSH::Buffer.from(:byte, KEXDH_GEX_REQUEST, :long, MINIMUM_BITS,
            :long, data[:need_bits], :long, MAXIMUM_BITS)
          connection.send_message(buffer)

          buffer = connection.next_message
          unless buffer.type == KEXDH_GEX_GROUP
            raise Net::SSH::Exception, "expected KEXDH_GEX_GROUP, got #{buffer.type}"
          end
          p = buffer.read_bignum
          g = buffer.read_bignum
        end
        puts "GEX PG: #{p} #{g} #{data[:need_bits]}"

        [p, g]
      end

      # Returns the INIT/REPLY constants used by this algorithm.
      def get_message_types
        [KEXDH_GEX_INIT, KEXDH_GEX_REPLY]
      end

      # Build the signature buffer to use when verifying a signature from
      # the server.
      def build_signature_buffer(result)
        response = Net::SSH::Buffer.new
        response.write_string data[:client_version_string],
                              data[:server_version_string],
                              data[:client_algorithm_packet],
                              data[:server_algorithm_packet],
                              result[:key_blob]
        response.write_long MINIMUM_BITS,
                            data[:need_bits],
                            MAXIMUM_BITS
        response.write_bignum dh.p, dh.g, dh.pub_key,
                              result[:server_dh_pubkey],
                              result[:shared_secret]
        response
      end
  end

end
=begin
Friedl/Provos/Simpson     expires in six months                 [Page 3]

INTERNET DRAFT                                                 July 2003


          length of k bits, where 1024 <= k <= 8192.  The recommended
          values for min and max are 1024 and 8192 respectively.

          Either side MUST NOT send or accept e or f values that are not
          in the range [1, p-1]. If this condition is violated, the key
          exchange fails.  To prevent confinement attacks, they MUST
          accept the shared secret K only if 1 < K < p - 1.


     The server should return the smallest group it knows that is larger
     than the size the client requested.  If the server does not know a
     group that is larger than the client request, then it SHOULD return
     the largest group it knows.  In all cases, the size of the returned
     group SHOULD be at least 1024 bits.

     This is implemented with the following messages.  The hash algo-
     rithm for computing the exchange hash is defined by the method
     name, and is called HASH.  The public key algorithm for signing is
     negotiated with the KEXINIT messages.

     First, the client sends:
       byte      SSH_MSG_KEY_DH_GEX_REQUEST
       uint32    min, minimal size in bits of an acceptable group
       uint32    n, preferred size in bits of the group the server should send
       uint32    max, maximal size in bits of an acceptable group

     The server responds with
       byte      SSH_MSG_KEX_DH_GEX_GROUP
       mpint     p, safe prime
       mpint     g, generator for subgroup in GF(p)

     The client responds with:
       byte      SSH_MSG_KEX_DH_GEX_INIT
       mpint     e, dh pubkey

     The server responds with:
       byte      SSH_MSG_KEX_DH_GEX_REPLY
       string    server public host key and certificates (K_S)
       mpint     f
       string    signature of H

     The hash H is computed as the HASH hash of the concatenation of the
     following:
       string    V_C, the client's version string (CR and NL excluded)
       string    V_S, the server's version string (CR and NL excluded)
       string    I_C, the payload of the client's SSH_MSG_KEXINIT
       string    I_S, the payload of the server's SSH_MSG_KEXINIT
       string    K_S, the host key

=end
