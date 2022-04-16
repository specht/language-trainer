#!/usr/bin/env ruby
SKIP_COLLECT_DATA = true
require './main.rb'

class Migrate1
    include QtsNeo4j
    
    def run
        rows = neo4j_query("MATCH (e:Event)-[:BELONGS_TO]->(u:User) RETURN e, u;")
        rows.each do |row|
            email = row['u'][:email]
            sha1 = row['e'][:sha1]
            timestamp = row['e'][:timestamp]
            STDERR.puts "#{sha1} #{timestamp} #{email}"
            neo4j_query(<<~END_OF_QUERY, {:email => email, :sha1 => sha1, :timestamp => timestamp})
                MERGE (u:User {email: $email})
                MERGE (e:Entry {sha1: $sha1})
                MERGE (e)-[r:BELONGS_TO]-(u)
                SET r.timestamp = $timestamp
            END_OF_QUERY
        end
        neo4j_query("MATCH (e:Event) DETACH DELETE e;")
        # STDERR.puts rows.to_yaml
    end
end

mig = Migrate1.new
mig.run
